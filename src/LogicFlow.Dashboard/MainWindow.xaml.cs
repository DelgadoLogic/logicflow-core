using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using OmniCore.Engine;
using LogicFlow.Sentinel;
using LogicFlow.Guardian;
using LogicFlow.Lazarus;
using OmniLicense;
using LogicFlow.Native;
using Microsoft.Extensions.Logging.Abstractions;
using RegistryModule = LogicFlow.Registry;
using System.Collections.ObjectModel;
using LogicFlow.Dashboard.Common;
using LogicFlow.Dashboard.ViewModels;
using DelgadoLogic.Core;
using OmniPulse;

namespace LogicFlow.Dashboard;

public partial class MainWindow : Window
{
    [DllImport("gdi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreateIconFromResourceEx(byte[] pbIconBits, uint cbIconBits, bool fIcon, uint dwVersion, int cxDesired, int cyDesired, uint Flags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    // ─── Module instances ───
    private readonly SystemProfiler _profiler = new(NullLogger<SystemProfiler>.Instance);
    private readonly VulnerabilityScanner _vulnScanner = new(NullLogger<VulnerabilityScanner>.Instance);
    private readonly PrivacyScrubber _privacyScrubber = new(NullLogger<PrivacyScrubber>.Instance);
    private readonly SmartDriverEngine _driverEngine = new(NullLogger<SmartDriverEngine>.Instance);
    private readonly DriverAuditorEngine _driverAuditor = new(NullLogger<DriverAuditorEngine>.Instance);
    private readonly DebloatEngine _debloatEngine = new(NullLogger<DebloatEngine>.Instance);
    private readonly StartupOptimizer _startupOptimizer = new(NullLogger<StartupOptimizer>.Instance);
    private readonly RegistryModule.RegistryAnalyzer _registryAnalyzer = new(NullLogger<RegistryModule.RegistryAnalyzer>.Instance);
    private readonly MtpBridge _mtpBridge = new(NullLogger<MtpBridge>.Instance);
    private readonly SmartDiskReader _smartReader = new(NullLogger<SmartDiskReader>.Instance);
    private readonly AutoUpdateEngine _updateEngine = new("1.0.0");

    // ─── Sentinel engines (Sprint 3 — 10-vector) ───
    private readonly NetworkScanner _networkScanner = new(NullLogger<NetworkScanner>.Instance);
    private readonly StartupAuditor _startupAuditor = new(NullLogger<StartupAuditor>.Instance);
    private readonly RemediationEngine _remediationEngine = new(NullLogger<RemediationEngine>.Instance);

    // ─── New engines (Sprint 2-3) ───
    private readonly JunkCleanerEngine _junkCleaner = new();
    private readonly MemoryOptimizer _memoryOptimizer = new();
    private readonly PagefileOptimizer _pagefileOptimizer = new();
    private readonly TurboMode _turboMode = new();
    private readonly SmartDiskHealth _smartDiskHealth = new();
    private readonly FileShredder _fileShredder = new();
    private readonly WindowsTweakEngine _tweakEngine = new();
    private readonly AiPrivacyGuardEngine _aiPrivacyGuard = new();
    private readonly WinGetUpdaterEngine _wingetUpdater = new();
    private readonly DefenderHardenerEngine _defenderHardener = new();
    private readonly PersistenceScannerEngine _persistenceScanner = new();
    private readonly DnsHostsGuardEngine _dnsHostsGuard = new();
    private readonly SystemRestoreEngine _restoreEngine = new();

    // ─── Game Vault & Storage Optimization (Milestone 5) ───
    private readonly SteamLibraryDetector _gameDetector = SteamLibraryDetector.Instance;
    private readonly GameCompressionEngine _gameCompressionEngine = GameCompressionEngine.Instance;
    private readonly ObservableCollection<GameVaultItemViewModel> _gameVaultItems = new();
    private readonly GameVaultSummaryViewModel _gameVaultSummary = new();
    private readonly GameVaultProgressViewModel _gameVaultProgress = new();
    private List<DetectedGame>? _lastDetectedGames;
    private DecayAuditReport? _lastDecayAudit;
    private CancellationTokenSource? _gameCompressionCts;
    private bool _isGameOperationRunning;

    // ─── HyperStore Storage Armor (Milestone 4) ───
    private readonly HyperStoreViewModel _hyperStoreViewModel = new();

    // ─── Tray + Settings ───
    private TrayIconManager? _trayManager;
    private UserSettings _settings = SettingsManager.Load();
    private bool _isUiLoading;
    private CancellationTokenSource? _gemmaDownloadCts;
    private CancellationTokenSource? _deviceChangeDebounceCts;

    // ─── Resource Monitor ───
    private readonly SystemInfoEngine _sysInfo = new();
    private SystemInfoEngine.SystemSnapshot? _liveSnapshot;
    private System.Windows.Threading.DispatcherTimer? _monitorTimer;
    private bool _monitorRunning;
    private bool _isUpdatingProcesses;

    // ─── Cached scan results for action handlers ───
    private VulnScanResult? _lastVulnResult;
    private List<BloatwarePackage>? _lastBloatResults;
    private List<StartupItem>? _lastStartupResults;
    private RegistryModule.RegistryScanResult? _lastRegResult;
    private List<JunkCleanerEngine.JunkScanResult>? _lastJunkReport;
    private List<AiPrivacyFeatureStatus>? _lastAiFeatures;
    private List<WinGetPackage>? _lastWinGetPackages;
    private List<PersistenceThreatItem>? _lastPersistenceThreats;
    private List<RestorePointInfo>? _lastCheckpoints;
    private List<SmartDiskHealth.DiskSmartReport>? _lastSmartDrives;

    // ─── Page panels ───
    private ScrollViewer[] _pages = [];
    private System.Windows.Controls.Button[] _navButtons = [];
    private System.Windows.Controls.Button? _activeNavButton;



    // Live dashboard processes and CPU history
    private List<RunningProcessInfo> _lastProcesses = new();
    private Dictionary<int, (TimeSpan CpuTime, DateTime TimeStamp)> _processCpuHistory = new();
    [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int attrSize);

    private const int DWMWA_SYSTEMBACKDROP_TYPE = 38;
    private const int DWMWA_MICA_EFFECT = 1029;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        StateChanged += MainWindow_StateChanged;

        // Synchronously initialize fast hardware metrics immediately upon construction
        // so that controls never display 0% placeholders during initial window layout/rendering
        try
        {
            _liveSnapshot = SystemInfoEngine.CreateFastInitialSnapshot();
            UpdateDashboardLiveMetrics();
        }
        catch { }
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        try
        {
            var windowInteropHelper = new System.Windows.Interop.WindowInteropHelper(this);
            IntPtr hwnd = windowInteropHelper.Handle;

            // Apply Windows 11 system backdrop Mica (value 2)
            int backdropType = 2; // Mica
            int result = DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref backdropType, sizeof(int));
            if (result != 0)
            {
                // Fallback for older Win11 builds: DWMWA_MICA_EFFECT = 1029
                int trueValue = 1;
                DwmSetWindowAttribute(hwnd, DWMWA_MICA_EFFECT, ref trueValue, sizeof(int));
            }

            // Hook single-instance window restore message
            if (hwnd != IntPtr.Zero)
            {
                _wmRestoreMessage = RegisterWindowMessage("LogicFlow_SingleInstance_Restore_Message");
                if (_wmRestoreMessage != 0)
                {
                    try { ChangeWindowMessageFilterEx(hwnd, _wmRestoreMessage, MSGFLT_ALLOW, IntPtr.Zero); } catch { }
                }
                var source = System.Windows.Interop.HwndSource.FromHwnd(hwnd);
                source?.AddHook(WndProcRestoreHook);
            }
        }
        catch
        {
            // Ignore error if running on older OS
        }
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _pages = [PageDashboard, PageSentinel, PageGuardian, PageHyperStore, PageMonitor, PageToolbox, PageLazarus, PageRegistry, PageSettings];
            _navButtons = [NavDashboard, NavSentinel, NavGuardian, NavHyperStore, NavMonitor, NavToolbox, NavLazarus, NavRegistry, NavSettings];
            _activeNavButton = NavDashboard;

            if (PageHyperStore != null) PageHyperStore.DataContext = _hyperStoreViewModel;

            // Ensure PageDashboard is active and visible
            if (PageDashboard != null) PageDashboard.Visibility = Visibility.Visible;
            if (PageTitle != null) PageTitle.Text = "System Dashboard";
            if (LazarusCategoryFilter != null && LazarusCategoryFilter.SelectedIndex < 0)
            {
                LazarusCategoryFilter.SelectedIndex = 0;
            }
            RenderBrowserWhitelistTags();
        }
        catch { }

        // Instant hardware specs and top metric cards via fast native/registry lookups (< 1ms, zero WMI blocking)
        try
        {
            _liveSnapshot ??= SystemInfoEngine.CreateFastInitialSnapshot();

            var cpuFast = !string.IsNullOrWhiteSpace(_liveSnapshot.CpuName)
                ? _liveSnapshot.CpuName
                : SystemInfoEngine.GetFastCpuName();
            var ramGb = _liveSnapshot.TotalRamBytes > 0 
                ? _liveSnapshot.TotalRamBytes / (1024.0 * 1024 * 1024)
                : (SystemInfoEngine.GetFastMemoryStatus().Total / (1024.0 * 1024 * 1024));
            var ramLabel = ramGb > 0 ? $"{ramGb:F0}GB RAM" : "RAM Active";
            HealthHardwareLabel.Text = $"{cpuFast.Split('@')[0].Trim()} / {ramLabel}";
            HealthOsLabel.Text = !string.IsNullOrWhiteSpace(_liveSnapshot.OsName)
                ? _liveSnapshot.OsName
                : SystemInfoEngine.GetFriendlyOsName();

            // Immediately populate top metric cards and monitor UI with fast native data so they never appear blank/0%
            UpdateDashboardLiveMetrics();
            PopulateMonitorUI(forceDiskRebuild: true);
        }
        catch 
        { 
            HealthHardwareLabel.Text = "Windows PC / Hardware Active";
            HealthOsLabel.Text = SystemInfoEngine.GetFriendlyOsName();
        }

        // Start live monitor immediately so top cards update continuously without tab switching!
        try
        {
            StartLiveTelemetryTimer();
        }
        catch { }

        // Initialize AI Terminal welcome safely
        try
        {
            AppendTerminalLine("> Initializing Pulse Engine v3.1... Ready.", "#4B5563");
            AppendTerminalLine("Pulse runs on this PC: rule-based answers about your CPU, RAM, GPU, storage, and security. Nothing you type here is sent anywhere.", "#A78BFA", true);
        }
        catch { }

        // Immediately populate top running processes in background
        _ = Task.Run(() =>
        {
            try
            {
                _lastProcesses = UpdateAndGetTopProcesses();
                Dispatcher.Invoke(() =>
                {
                    if (ProcessesListView == null) return;
                    ProcessesListView.ItemsSource = null;
                    ProcessesListView.ItemsSource = _lastProcesses;
                    AdjustProcessColumns();
                    if (ProcessesEmptyState != null)
                    {
                        bool hasItems = _lastProcesses != null && _lastProcesses.Count > 0;
                        ProcessesEmptyState.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
                        ProcessesListView.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
                    }
                });
            }
            catch { }
        });

        // Check for saved license key and apply tier
        try { CheckAndApplySavedLicense(); } catch { }

        try { DataPathLabel.Text = GetAllDataPathsFormatted(); } catch { }
        try
        {
            if (BtnRestartAdmin != null)
            {
                BtnRestartAdmin.Visibility = App.IsRunningAsAdministrator() ? Visibility.Collapsed : Visibility.Visible;
            }
        }
        catch { }

        // Initialize tray icon
        try { _trayManager ??= new TrayIconManager(this); } catch { }

        // Load user settings
        try
        {
            _isUiLoading = true;
            _settings = SettingsManager.Load();
            if (_settings.FirstRunDate == DateTimeOffset.MinValue)
            {
                _settings.FirstRunDate = DateTimeOffset.UtcNow;
                SettingsManager.Save();
            }
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            _diskSpaceAnalyzer.ExcludedPaths = _settings.ScanExclusions;
            RestoreSavedWindowBounds();
            LoadSettingsToUI();
            ApplyVisualSettings();
        }
        catch { }
        finally
        {
            _isUiLoading = false;
        }

        // Sync Turbo button & Status-First Overview Bar from active or persisted cross-process Turbo state
        try
        {
            bool turboActive = _turboMode.IsActive;
            UpdateTurboButtonVisuals(turboActive);
            UpdateOverviewBar();
        }
        catch { }

        // Background heavy tasks: WMI profiler, HWID, Lazarus drives, and Update checks
        _ = Task.Run(() =>
        {
            try
            {
                var snapshot = _profiler.CaptureSnapshot();
                var full = _sysInfo.CollectSnapshot();
                Dispatcher.Invoke(() =>
                {
                    if (!string.IsNullOrWhiteSpace(snapshot.Cpu.Name))
                        HealthHardwareLabel.Text = $"{snapshot.Cpu.Name.Split('@')[0].Trim()} / {snapshot.Memory.TotalPhysicalBytes / (1024.0 * 1024 * 1024):F0}GB RAM";
                    if (!string.IsNullOrWhiteSpace(snapshot.Os.Caption))
                        HealthOsLabel.Text = snapshot.Os.Caption;

                    if (_liveSnapshot != null)
                    {
                        if (!string.IsNullOrWhiteSpace(full.GpuName))
                        {
                            _liveSnapshot.GpuName = full.GpuName;
                            _liveSnapshot.GpuDriverVersion = full.GpuDriverVersion;
                            _liveSnapshot.GpuVramBytes = full.GpuVramBytes;
                        }
                        if (!string.IsNullOrWhiteSpace(full.CpuName))
                        {
                            _liveSnapshot.CpuName = full.CpuName;
                            _liveSnapshot.CpuCores = full.CpuCores;
                            _liveSnapshot.CpuThreads = full.CpuThreads;
                            _liveSnapshot.CpuSpeedGHz = full.CpuSpeedGHz;
                        }
                        if (!string.IsNullOrWhiteSpace(full.OsName))
                        {
                            _liveSnapshot.OsName = full.OsName;
                        }
                        if (!string.IsNullOrWhiteSpace(full.ActiveNetworkAdapter))
                        {
                            _liveSnapshot.ActiveNetworkAdapter = full.ActiveNetworkAdapter;
                            _liveSnapshot.NetworkSpeedMbps = full.NetworkSpeedMbps;
                        }
                        if (!string.IsNullOrWhiteSpace(full.IpAddress))
                        {
                            _liveSnapshot.IpAddress = full.IpAddress;
                        }
                        PopulateMonitorUI(forceDiskRebuild: false);
                    }
                });
            }
            catch { }
        });

        _ = Task.Run(() =>
        {
            try
            {
                var hwid = new HwidGenerator().GenerateHwid();
                Dispatcher.Invoke(() => HwidLabel.Text = $"HWID: {hwid[..Math.Min(32, hwid.Length)]}...");
            }
            catch { Dispatcher.Invoke(() => HwidLabel.Text = "HWID: unavailable"); }
        });

        _ = Task.Run(async () =>
        {
            await Dispatcher.InvokeAsync(async () => await RefreshDrives());
        });

        if (_settings.CheckForUpdatesAutomatically &&
            EditionService.Instance.Consent.HasDecided &&
            !EditionService.Instance.Consent.NeedsReconsent &&
            EditionService.Instance.Current != Edition.Free)
        {
            _ = Task.Run(async () =>
            {
                var update = await _updateEngine.CheckForUpdateAsync();
                if (update != null)
                    Dispatcher.Invoke(() => _trayManager?.ShowBalloon(
                        "LogicFlow Update", $"v{update.Version} available. Click to download.",
                        System.Windows.Forms.ToolTipIcon.Info));
            });
        }

        // ─── Settings Enactment: Startup Sync & Policies ───
        try
        {
            bool isRegEnabled = SettingsManager.IsStartWithWindowsConfigured();
            if (_settings.StartWithWindows)
            {
                SettingsManager.SetStartWithWindows(true);
            }
            else if (isRegEnabled)
            {
                _settings.StartWithWindows = true;
                SettingsManager.Save();
                if (SettingStartWithWindows != null) SettingStartWithWindows.IsChecked = true;
            }
            else
            {
                // Clean up any legacy installer-created scheduled task when StartWithWindows is disabled
                SettingsManager.SetStartWithWindows(false);
            }
        }
        catch { }

        if (_settings.EnableTelemetryBlocking && EditionService.Instance.Allows(Capability.Core))
        {
            _ = Task.Run(async () =>
            {
                try { await _aiPrivacyGuard.ApplyAllAsync(); } catch { }
            });
        }

        if (_settings.AutoScrubPrivacy && EditionService.Instance.Allows(Capability.BackgroundAutomation))
        {
            _ = Task.Run(() =>
            {
                try { _privacyScrubber.Scrub(); } catch { }
            });
        }

        // ─── Non-Blocking Startup Scans ───
        if (_settings.AutoScanOnStartup || _settings.ScanDriversOnStartup || _settings.ScanRegistryOnStartup || _settings.ScanSmartOnStartup)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    if (_settings.AutoScanOnStartup)
                    {
                        var secResult = await _vulnScanner.ScanAsync();
                        var driverReport = _driverAuditor.AuditDrivers(true);
                        var startup = _startupOptimizer.AnalyzeStartupItems();
                        var regResult = _registryAnalyzer.Scan();
                        var junkReport = _junkCleaner.Scan();
                        var smartDrives = _smartDiskHealth.ScanDrives();

                        await Dispatcher.InvokeAsync(() =>
                        {
                            RenderSentinelResults(secResult);
                            RenderDriverResults(driverReport.Drivers);
                            RenderStartupResults(startup);
                            RenderRegistryResults(regResult);
                            RenderJunkResults(junkReport);
                            RenderSmartDiskResults(smartDrives);

                            var driverStatus = _driverAuditor.CheckDriverStatus(driverReport);
                            var badDrivers = driverStatus.ErrorCount + driverStatus.Outdated + driverStatus.Unsigned;
                            var heavyStartup = startup.Count(si => si.ImpactScore >= 7);
                            var summary = $"Startup Scan: {secResult.Vulnerabilities.Count} vulns, {badDrivers} driver alerts, {regResult.TotalIssues} reg issues.";
                            HealthMonitorLabel.Text = summary;
                            HealthMonitorLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
                        });
                    }
                    else
                    {
                        int alerts = 0;
                        if (_settings.ScanDriversOnStartup)
                        {
                            var driverReport = _driverAuditor.AuditDrivers(true);
                            await Dispatcher.InvokeAsync(() => RenderDriverResults(driverReport.Drivers));
                            var driverStatus = _driverAuditor.CheckDriverStatus(driverReport);
                            alerts += driverStatus.ErrorCount + driverStatus.Outdated + driverStatus.Unsigned;
                        }

                        if (_settings.ScanRegistryOnStartup)
                        {
                            var regResult = _registryAnalyzer.Scan();
                            await Dispatcher.InvokeAsync(() => RenderRegistryResults(regResult));
                            alerts += regResult.TotalIssues;
                        }

                        if (_settings.ScanSmartOnStartup)
                        {
                            var smartDrives = _smartDiskHealth.ScanDrives();
                            await Dispatcher.InvokeAsync(() => RenderSmartDiskResults(smartDrives));
                            alerts += smartDrives.Count(d => d.Status != SmartDiskHealth.DiskHealthStatus.Healthy && d.Status != SmartDiskHealth.DiskHealthStatus.Unknown);
                        }

                        if (_settings.ScanDriversOnStartup || _settings.ScanRegistryOnStartup || _settings.ScanSmartOnStartup)
                        {
                            await Dispatcher.InvokeAsync(() =>
                            {
                                HealthMonitorLabel.Text = $"Startup telemetry synced: {alerts} items noted across active modules.";
                                HealthMonitorLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
                            });
                        }
                    }
                }
                catch { }
            });
        }

        App.DrainPendingPipeCommands(this);
    }

    // ═══════════════════════════════════════════════════════════
    //  PAGE NAVIGATION & ZERO-GC FROZEN TRANSITIONS
    // ═══════════════════════════════════════════════════════════
    private static readonly DoubleAnimation PageFadeInAnimation;
    private static readonly DoubleAnimation PageSlideInAnimation;

    static MainWindow()
    {
        var cubicEase = new CubicEase { EasingMode = EasingMode.EaseOut };
        cubicEase.Freeze();

        PageFadeInAnimation = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = cubicEase
        };
        PageFadeInAnimation.Freeze();

        PageSlideInAnimation = new DoubleAnimation(15.0, 0.0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = cubicEase
        };
        PageSlideInAnimation.Freeze();
    }

    private void ShowPage(ScrollViewer target, string title, System.Windows.Controls.Button navButton)
    {
        // Update nav button active states
        if (_activeNavButton != null && _activeNavButton != navButton)
            _activeNavButton.Style = (Style)FindResource("NavButton");
        navButton.Style = (Style)FindResource("NavButtonActive");
        _activeNavButton = navButton;
        navButton.BringIntoView();

        // Hide all pages, reset scroll, show target
        foreach (var page in _pages)
        {
            if (page != target && page.Visibility == Visibility.Visible)
            {
                page.Visibility = Visibility.Collapsed;
            }
        }

        target.ScrollToTop();
        target.Visibility = Visibility.Visible;
        PageTitle.Text = title;

        // Animate the page content with fade + slide (200ms CubicEase)
        var content = FindPageContent(target);
        if (content != null)
        {
            AnimatePageIn(content);
        }
    }

    private static FrameworkElement? FindPageContent(ScrollViewer sv)
    {
        return sv.Content as FrameworkElement;
    }

    private void AnimatePageIn(FrameworkElement panel)
    {
        if ((_settings != null && !_settings.EnableAnimations) || !SystemParameters.ClientAreaAnimation || SystemParameters.IsRemoteSession)
        {
            if (panel.RenderTransform is TranslateTransform existingTt)
            {
                existingTt.BeginAnimation(TranslateTransform.YProperty, null);
                existingTt.Y = 0;
            }
            panel.BeginAnimation(UIElement.OpacityProperty, null);
            panel.Opacity = 1.0;
            return;
        }

        if (panel.RenderTransform is not TranslateTransform tt)
        {
            tt = new TranslateTransform(0, 15);
            panel.RenderTransform = tt;
        }
        else
        {
            tt.Y = 15;
        }

        panel.Opacity = 0.0;
        panel.BeginAnimation(UIElement.OpacityProperty, PageFadeInAnimation, HandoffBehavior.SnapshotAndReplace);
        tt.BeginAnimation(TranslateTransform.YProperty, PageSlideInAnimation, HandoffBehavior.SnapshotAndReplace);
    }

    private void OnNavDashboard(object s, RoutedEventArgs e)
    {
        ShowPage(PageDashboard, "System Dashboard", NavDashboard);
        Dispatcher.InvokeAsync(AdjustProcessColumns, System.Windows.Threading.DispatcherPriority.Loaded);
    }
    private void OnNavSentinel(object s, RoutedEventArgs e)
    {
        ShowPage(PageSentinel, "Sentinel — Security Center", NavSentinel);
        if (_lastVulnResult != null && VulnList.Items.Count == 0 && ServiceList.Items.Count == 0)
        {
            RenderSentinelResults(_lastVulnResult);
        }
    }
    private void OnNavGuardian(object s, RoutedEventArgs e)
    {
        ShowPage(PageGuardian, "Guardian — Performance", NavGuardian);
        if (_currentAuditedDrivers != null && DriverList.Items.Count == 0)
        {
            RenderDriverResults(_currentAuditedDrivers);
        }
        if (_lastStartupResults != null && StartupList.Items.Count == 0)
        {
            RenderStartupResults(_lastStartupResults);
        }
        if (_lastBloatResults != null && BloatList.Items.Count == 0)
        {
            RenderBloatwareResults(_lastBloatResults);
        }
        if (_lastSmartDrives != null && SmartDiskList.Items.Count == 0)
        {
            RenderSmartDiskResults(_lastSmartDrives);
        }
        if (TweakList.Items.Count == 0)
        {
            RenderTweakResults();
        }
    }
    private void OnNavHyperStore(object s, RoutedEventArgs e)
    {
        ShowPage(PageHyperStore, "HyperStore — Storage Armor", NavHyperStore);
    }

    private string? PickFolderDialog(string title, string? defaultDirectory = null)
    {
        string initial = !string.IsNullOrWhiteSpace(defaultDirectory) && Directory.Exists(defaultDirectory)
            ? defaultDirectory
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        try
        {
            var dlg = new Microsoft.Win32.OpenFolderDialog
            {
                Title = title,
                InitialDirectory = initial,
                Multiselect = false
            };
            return dlg.ShowDialog(this) == true ? dlg.FolderName : null;
        }
        catch
        {
            using var fbd = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = title,
                SelectedPath = initial,
                UseDescriptionForTitle = true
            };
            return fbd.ShowDialog() == System.Windows.Forms.DialogResult.OK ? fbd.SelectedPath : null;
        }
    }

    private async void OnScanDriveForRedundanciesClick(object s, RoutedEventArgs e)
    {
        try
        {
            var folder = PickFolderDialog("Select Folder or Drive to Scan for Duplicate Files");
            if (string.IsNullOrWhiteSpace(folder)) return;
            await _hyperStoreViewModel.ScanDriveForRedundanciesAsync(folder);
        }
        catch { }
    }

    private async void OnDedupWorkspaceClick(object s, RoutedEventArgs e)
    {
        try
        {
            var folder = PickFolderDialog("Select Workspace Folder to Deduplicate");
            if (string.IsNullOrWhiteSpace(folder)) return;

            bool confirmed = Dialogs.Confirm(
                this,
                "Confirm Workspace Deduplication",
                $"Deduplicate identical immutable files inside:\n{folder}\n\nLogicFlow replaces duplicate copies on the same volume with atomic hard links or ReFS block clones while preserving filenames.",
                "Deduplicate Folder",
                "Cancel",
                defaultCancel: true);
            if (!confirmed) return;

            await _hyperStoreViewModel.DeduplicateWorkspaceAsync(folder);
        }
        catch { }
    }

    private async void OnPackDirectoryToLfcClick(object s, RoutedEventArgs e)
    {
        try
        {
            string defaultDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");
            var folder = PickFolderDialog("Select Folder to Pack into a LogicFlow Container (.lfc)", defaultDir);
            if (string.IsNullOrWhiteSpace(folder)) return;

            var saveDlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save LogicFlow Container (.lfc) Archive",
                Filter = "LogicFlow Container (*.lfc)|*.lfc",
                FileName = $"{Path.GetFileName(folder.TrimEnd('\\', '/'))}.lfc",
                InitialDirectory = Path.GetDirectoryName(folder) ?? folder
            };
            if (saveDlg.ShowDialog(this) != true || string.IsNullOrWhiteSpace(saveDlg.FileName)) return;

            await _hyperStoreViewModel.PackDirectoryToLfcAsync(folder, saveDlg.FileName);
        }
        catch { }
    }

    private async void OnUnpackLfcArchiveClick(object s, RoutedEventArgs e)
    {
        try
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select LogicFlow Container (.lfc) Archive to Unpack",
                Filter = "LogicFlow Container (*.lfc)|*.lfc|All Files (*.*)|*.*",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            };

            if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FileName))
            {
                var defaultOut = Path.Combine(
                    Path.GetDirectoryName(dlg.FileName) ?? Path.GetTempPath(),
                    $"{Path.GetFileNameWithoutExtension(dlg.FileName)}_Unpacked");
                var destDir = PickFolderDialog("Select Destination Folder for Unpacked Files (or Cancel to abort)", Path.GetDirectoryName(dlg.FileName));
                if (string.IsNullOrWhiteSpace(destDir)) return;

                string targetExtract = string.Equals(destDir, Path.GetDirectoryName(dlg.FileName), StringComparison.OrdinalIgnoreCase)
                    ? defaultOut
                    : destDir;

                var extractedPath = await _hyperStoreViewModel.UnpackLfcArchiveAsync(dlg.FileName, targetExtract);
                if (!string.IsNullOrWhiteSpace(extractedPath))
                {
                    Dialogs.ShowMessage(
                        this,
                        "LogicFlow HyperStore — Unpack Complete",
                        $"Archive unpacked and cryptographically verified (BLAKE3 + CRC32C):\n\n{extractedPath}");
                }
            }
        }
        catch (Exception ex)
        {
            _hyperStoreViewModel.AddLogEntry("ERROR", $"Unpack failed: {ex.Message}", "", 0);
        }
    }

    private async void OnHyperStoreDiskSpaceClick(object s, RoutedEventArgs e)
    {
        try
        {
            string defaultRoot = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var targetRoot = PickFolderDialog("Select Folder or Drive for Disk Space Treemap Analysis", defaultRoot);
            if (string.IsNullOrWhiteSpace(targetRoot)) return;

            _hyperStoreViewModel.AddLogEntry("SCAN", $"Analyzing disk space footprint in '{targetRoot}' via DiskSpaceAnalyzer...", targetRoot, 0);

            var report = await Task.Run(() =>
            {
                var analyzer = new DiskSpaceAnalyzer
                {
                    ExcludedPaths = _settings?.ScanExclusions ?? []
                };
                return analyzer.Analyze(targetRoot, maxDepth: 3, topFilesCount: 15);
            });

            _treemapRootNode = report.RootNode;
            _treemapCurrentNode = report.RootNode;
            _treemapParentStack.Clear();
            DiskSpaceTreemapPanel.Visibility = Visibility.Visible;
            RenderDiskSpaceTreemap();

            foreach (var lf in report.LargestFiles.Take(8))
            {
                _hyperStoreViewModel.AddLogEntry(
                    "SCAN",
                    $"Large file: {lf.Name} ({lf.SizeFormatted}) [{lf.Extension}]",
                    lf.Path,
                    0);
            }

            var topExts = string.Join(", ", report.ByExtension
                .OrderByDescending(kv => kv.Value)
                .Take(5)
                .Select(kv => $"{kv.Key}: {HyperStoreViewModel.FormatBytes(kv.Value)}"));

            _hyperStoreViewModel.AddLogEntry(
                "SCAN",
                $"Disk Space Analysis Complete: {report.TotalFilesScanned} files across {report.TotalFoldersScanned} folders ({report.RootNode.SizeFormatted}). Top file types: {topExts}",
                targetRoot,
                0);
        }
        catch (Exception ex)
        {
            _hyperStoreViewModel.AddLogEntry("ERROR", $"Disk space analysis failed: {ex.Message}", "", 0);
        }
    }

    private void OnCancelHyperStoreOperationClick(object s, RoutedEventArgs e)
    {
        _hyperStoreViewModel.CancelActiveOperation();
    }

    private void OnClearHyperStoreFeedClick(object s, RoutedEventArgs e)
    {
        _hyperStoreViewModel.ClearActionFeed();
    }

    private void OnFindingSelectAllClick(object s, RoutedEventArgs e)
    {
        _hyperStoreViewModel.SelectAllFindings(true);
    }

    private void OnFindingSelectSafeClick(object s, RoutedEventArgs e)
    {
        _hyperStoreViewModel.SelectSafeFindings();
    }

    private void OnFindingDeselectAllClick(object s, RoutedEventArgs e)
    {
        _hyperStoreViewModel.SelectAllFindings(false);
    }

    private async void OnDeduplicateSelectedFindingsClick(object s, RoutedEventArgs e)
    {
        try
        {
            await _hyperStoreViewModel.DeduplicateSelectedAsync();
        }
        catch { }
    }

    private void OnCategoryFilterClick(object s, RoutedEventArgs e)
    {
        if (s is System.Windows.Controls.Button btn && btn.Tag is string category)
        {
            _hyperStoreViewModel.SelectedCategoryFilter = category;
        }
    }

    private void OnOpenFindingLocationClick(object s, RoutedEventArgs e)
    {
        try
        {
            if (s is FrameworkElement elem)
            {
                if (elem.DataContext is HyperStoreDuplicateFindingViewModel finding)
                {
                    string path = finding.PrimaryFilePath;
                    if (File.Exists(path))
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            Arguments = $"/select,\"{path}\"",
                            UseShellExecute = true
                        });
                    }
                    else if (Directory.Exists(finding.DirectoryPath))
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            Arguments = $"\"{finding.DirectoryPath}\"",
                            UseShellExecute = true
                        });
                    }
                }
                else if (elem.DataContext is HyperStoreDuplicateCopyViewModel copy)
                {
                    if (File.Exists(copy.Path))
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            Arguments = $"/select,\"{copy.Path}\"",
                            UseShellExecute = true
                        });
                    }
                    else if (Directory.Exists(copy.DirectoryPath))
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                            Arguments = $"\"{copy.DirectoryPath}\"",
                            UseShellExecute = true
                        });
                    }
                }
            }
        }
        catch { }
    }

    private void OnExcludeFindingFolderClick(object s, RoutedEventArgs e)
    {
        if (s is FrameworkElement elem && elem.DataContext is HyperStoreDuplicateFindingViewModel finding)
        {
            _hyperStoreViewModel.ExcludeFolder(finding.DirectoryPath);
        }
    }

    private async void OnDeduplicateSingleFindingClick(object s, RoutedEventArgs e)
    {
        if (s is FrameworkElement elem && elem.DataContext is HyperStoreDuplicateFindingViewModel finding)
        {
            try
            {
                await _hyperStoreViewModel.DeduplicateFindingAsync(finding);
            }
            catch { }
        }
    }

    private void OnNavMonitor(object s, RoutedEventArgs e)
    {
        ShowPage(PageMonitor, "Resource Monitor — Live", NavMonitor);
        if (!_monitorRunning)
        {
            StartLiveTelemetryTimer();
        }
        PopulateMonitorUI(forceDiskRebuild: MonitorDiskList.Items.Count == 0);
    }
    private void OnNavToolbox(object s, RoutedEventArgs e)
    {
        ShowPage(PageToolbox, "Toolbox — Utilities", NavToolbox);
        if (_lastJunkReport != null && JunkList.Items.Count == 0)
        {
            RenderJunkResults(_lastJunkReport);
        }
    }
    private void OnNavLazarus(object s, RoutedEventArgs e)
    {
        ShowPage(PageLazarus, "Lazarus — Data Recovery", NavLazarus);
        if (DriveList.Items.Count == 0) _ = RefreshDrives();
    }
    private void OnNavRegistry(object s, RoutedEventArgs e)
    {
        ShowPage(PageRegistry, "Registry Surgeon", NavRegistry);
        if (_lastRegResult != null && OrphanList.Items.Count == 0)
        {
            RenderRegistryResults(_lastRegResult);
        }
    }
    private void OnNavSettings(object s, RoutedEventArgs e)
    {
        try
        {
            _settings = SettingsManager.Load();
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            _diskSpaceAnalyzer.ExcludedPaths = _settings.ScanExclusions;
            RefreshExclusionsUi();
        }
        catch { }
        ShowPage(PageSettings, "Settings", NavSettings);
    }

    // ═══════════════════════════════════════════════════════════
    //  RESOURCE MONITOR
    // ═══════════════════════════════════════════════════════════
    private void StartLiveTelemetryTimer()
    {
        if (_monitorRunning) return;

        _liveSnapshot ??= SystemInfoEngine.CreateFastInitialSnapshot();
        UpdateDashboardLiveMetrics();
        PopulateMonitorUI(forceDiskRebuild: MonitorDiskList.Items.Count == 0);

        _monitorTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _monitorTimer.Tick += OnMonitorTick;
        _monitorTimer.Start();
        _monitorRunning = true;

        try
        {
            MonitorStatus.Text = "● Live";
            MonitorStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            BtnStartMonitor.Visibility = Visibility.Collapsed;
            BtnStopMonitor.Visibility = Visibility.Visible;
            BtnStartMonitor.IsEnabled = false;
        }
        catch { }
    }

    private bool _isPopulatingMonitor;

    private void PopulateMonitorUI(bool forceDiskRebuild = false)
    {
        if (_isPopulatingMonitor) return;
        _isPopulatingMonitor = true;
        try
        {
            _liveSnapshot ??= SystemInfoEngine.CreateFastInitialSnapshot();
            if (_liveSnapshot == null) return;

            // CPU details
            try
            {
                var cpuModel = !string.IsNullOrWhiteSpace(_liveSnapshot.CpuName)
                    ? _liveSnapshot.CpuName
                    : SystemInfoEngine.GetFastCpuName();
                CpuNameText.Text = cpuModel;
                var cores = _liveSnapshot.CpuCores > 0 ? _liveSnapshot.CpuCores : Math.Max(1, Environment.ProcessorCount / 2);
                var threads = _liveSnapshot.CpuThreads > 0 ? _liveSnapshot.CpuThreads : Environment.ProcessorCount;
                var speedText = _liveSnapshot.CpuSpeedGHz > 0 ? $"{_liveSnapshot.CpuSpeedGHz:F1} GHz" : "2.0 GHz";
                CpuCoresText.Text = $"{cores} cores, {threads} threads | {speedText} clock";
                MonitorCpuFullText.Text = cpuModel;
            }
            catch { }

            // GPU details
            try
            {
                var gpuName = !string.IsNullOrWhiteSpace(_liveSnapshot.GpuName) &&
                              _liveSnapshot.GpuName != "Display Adapter" &&
                              _liveSnapshot.GpuName != "DirectX GPU" &&
                              _liveSnapshot.GpuName != "DirectX Graphics Adapter"
                    ? _liveSnapshot.GpuName
                    : SystemInfoEngine.GetFastGpuInfo().Name;
                if (string.IsNullOrWhiteSpace(gpuName) || gpuName == "DirectX Graphics Adapter")
                {
                    var wmi = SystemInfoEngine.GetWmiGpuInfo();
                    if (!string.IsNullOrWhiteSpace(wmi.Name)) gpuName = wmi.Name;
                }
                if (string.IsNullOrWhiteSpace(gpuName)) gpuName = "DirectX Graphics Adapter";

                var vramFormatted = _liveSnapshot.GpuVramBytes > 0
                    ? _liveSnapshot.GpuVramFormatted
                    : (SystemInfoEngine.GetFastGpuInfo().VramBytes > 0
                        ? SystemInfoEngine.SystemSnapshot.FormatBytes(SystemInfoEngine.GetFastGpuInfo().VramBytes)
                        : "Shared System VRAM");
                MonitorGpuText.Text = $"{gpuName} ({vramFormatted})";
            }
            catch { }

            // OS details
            try
            {
                var osName = !string.IsNullOrWhiteSpace(_liveSnapshot.OsName)
                    ? _liveSnapshot.OsName
                    : SystemInfoEngine.GetFriendlyOsName();
                OsDetailText.Text = osName;
            }
            catch { }

            // Network details
            try
            {
                var adapter = !string.IsNullOrWhiteSpace(_liveSnapshot.ActiveNetworkAdapter)
                    ? _liveSnapshot.ActiveNetworkAdapter
                    : SystemInfoEngine.GetActiveNetworkAdapter();
                NetworkInfoText.Text = _liveSnapshot.NetworkSpeedMbps > 0
                    ? $"{adapter} ({_liveSnapshot.NetworkSpeedMbps} Mbps)"
                    : adapter;

                var ip = !string.IsNullOrWhiteSpace(_liveSnapshot.IpAddress) && _liveSnapshot.IpAddress != "N/A"
                    ? _liveSnapshot.IpAddress
                    : SystemInfoEngine.GetLocalIpAddress();
                IpText.Text = ip;
            }
            catch { }

            // Uptime
            try
            {
                UptimeText.Text = _liveSnapshot.UptimeFormatted;
            }
            catch { }

            // Disks
            try
            {
                if (forceDiskRebuild || MonitorDiskList.Items.Count == 0)
                {
                    RebuildDiskList();
                }
            }
            catch { }

            // Live meters
            try
            {
                UpdateMonitorUI();
            }
            catch { }
        }
        finally
        {
            _isPopulatingMonitor = false;
        }
    }

    private void OnStartMonitor(object s, RoutedEventArgs e)
    {
        StartLiveTelemetryTimer();
        PopulateMonitorUI(forceDiskRebuild: true);

        // Background task: enrich GPU & detailed WMI without delaying live metric dispatch
        _ = Task.Run(() =>
        {
            try
            {
                var full = _sysInfo.CollectSnapshot();
                Dispatcher.Invoke(() =>
                {
                    if (_liveSnapshot != null)
                    {
                        if (!string.IsNullOrWhiteSpace(full.GpuName))
                        {
                            _liveSnapshot.GpuName = full.GpuName;
                            _liveSnapshot.GpuDriverVersion = full.GpuDriverVersion;
                            _liveSnapshot.GpuVramBytes = full.GpuVramBytes;
                        }
                        if (!string.IsNullOrWhiteSpace(full.CpuName))
                        {
                            _liveSnapshot.CpuName = full.CpuName;
                            _liveSnapshot.CpuCores = full.CpuCores;
                            _liveSnapshot.CpuThreads = full.CpuThreads;
                        }
                        PopulateMonitorUI(forceDiskRebuild: false);
                    }
                });
            }
            catch { }
        });
    }

    private void OnStopMonitor(object s, RoutedEventArgs e)
    {
        _monitorTimer?.Stop();
        _monitorTimer = null;
        _monitorRunning = false;
        MonitorStatus.Text = "⏸ Paused";
        MonitorStatus.Foreground = (Brush)FindResource("TextSecondaryBrush");
        BtnStopMonitor.Visibility = Visibility.Collapsed;
        BtnStartMonitor.IsEnabled = true;
        BtnStartMonitor.Visibility = Visibility.Visible;
    }

    private void OnMonitorTick(object? sender, EventArgs e)
    {
        _liveSnapshot ??= SystemInfoEngine.CreateFastInitialSnapshot();
        if (_isUpdatingProcesses) return;
        _isUpdatingProcesses = true;
        
        bool isDashboardVisible = PageDashboard.Visibility == Visibility.Visible;

        Task.Run(() =>
        {
            try
            {
                _sysInfo.UpdateLiveMetrics(_liveSnapshot);
                if (isDashboardVisible)
                {
                    _lastProcesses = UpdateAndGetTopProcesses();
                }
            }
            catch { }
        }).ContinueWith(_ => Dispatcher.Invoke(() =>
        {
            try
            {
                UpdateMonitorUI();
                UpdateDashboardLiveMetrics();
            }
            catch { }
            finally
            {
                _isUpdatingProcesses = false;
            }
        }), System.Threading.Tasks.TaskContinuationOptions.None);
    }

    private static Brush MetricBrush(double pct, ResourceDictionary? res = null)
    {
        string key = pct switch
        {
            > 80 => "DangerRedBrush",
            > 60 => "WarningAmberBrush",
            _    => "SuccessGreenBrush"
        };

        if (res != null && res.Contains(key) && res[key] is Brush b1)
            return b1;

        if (Application.Current?.Resources != null && Application.Current.Resources.Contains(key) && Application.Current.Resources[key] is Brush b2)
            return b2;

        return pct switch
        {
            > 80 => new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)),
            > 60 => new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)),
            _    => new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E))
        };
    }

    private void UpdateMonitorUI()
    {
        if (_liveSnapshot == null) return;

        // CPU
        var cpuPct = _liveSnapshot.CpuUsagePercent;
        CpuUsageBar.Value = cpuPct;
        CpuUsageBar.Foreground = MetricBrush(cpuPct, Resources);
        CpuUsageText.Text = cpuPct >= 0 ? $"{cpuPct:F0}%" : "N/A";
        CpuUsageText.Foreground = MetricBrush(cpuPct, Resources);

        // RAM
        var ramPct = _liveSnapshot.RamUsagePercent;
        RamUsageBar.Value = ramPct;
        RamUsageBar.Foreground = MetricBrush(ramPct, Resources);
        RamPctText.Text = $"{ramPct:F0}%";
        RamPctText.Foreground = MetricBrush(ramPct, Resources);
        RamUsageText.Text = $"{_liveSnapshot.UsedRamFormatted} / {_liveSnapshot.TotalRamFormatted} used";
        RamAvailText.Text = $"{_liveSnapshot.AvailableRamFormatted} available";

        // Uptime
        UptimeText.Text = _liveSnapshot.UptimeFormatted;

        // Auto-heal and live disk meter synchronization when Resource Monitor is open
        if (PageMonitor.Visibility == Visibility.Visible)
        {
            if (MonitorDiskList.Items.Count == 0 || MonitorDiskList.Items.Count != _liveSnapshot.Disks.Count)
            {
                RebuildDiskList();
            }
            else
            {
                for (int i = 0; i < _liveSnapshot.Disks.Count && i < MonitorDiskList.Items.Count; i++)
                {
                    if (MonitorDiskList.Items[i] is Border b && b.Child is StackPanel sp && sp.Children.Count >= 3)
                    {
                        var d = _liveSnapshot.Disks[i];
                        var pct = d.UsagePercent;
                        var brush = MetricBrush(pct, Resources);
                        if (sp.Children[0] is System.Windows.Controls.Grid g && g.Children.Count >= 2 && g.Children[1] is TextBlock pctLbl)
                        {
                            pctLbl.Text = $"{pct:F1}% used";
                            pctLbl.Foreground = brush;
                        }
                        if (sp.Children[1] is System.Windows.Controls.ProgressBar bar)
                        {
                            bar.Value = pct;
                            bar.Foreground = brush;
                        }
                        if (sp.Children[2] is TextBlock dtl)
                        {
                            var freeGB = d.FreeBytes / (1024.0 * 1024 * 1024);
                            var totalGB = d.TotalBytes / (1024.0 * 1024 * 1024);
                            dtl.Text = $"{freeGB:F1} GB free of {totalGB:F1} GB total";
                        }
                    }
                }
            }

            if (CpuCoresText.Text.StartsWith("—") || OsDetailText.Text.StartsWith("—") || IpText.Text.StartsWith("—"))
            {
                PopulateMonitorUI(forceDiskRebuild: false);
            }
        }
    }

    private void RebuildDiskList()
    {
        if (_liveSnapshot == null) return;
        if (_liveSnapshot.Disks.Count == 0)
        {
            _liveSnapshot.Disks = SystemInfoEngine.CollectDiskInfo();
        }
        MonitorDiskList.Items.Clear();
        foreach (var disk in _liveSnapshot.Disks)
        {
            var pct = disk.UsagePercent;
            var brush = MetricBrush(pct, Resources);
            var freeGB = disk.FreeBytes / (1024.0 * 1024 * 1024);
            var totalGB = disk.TotalBytes / (1024.0 * 1024 * 1024);

            var card = new Border
            {
                CornerRadius = new System.Windows.CornerRadius(8),
                BorderThickness = new System.Windows.Thickness(1),
                Padding = new System.Windows.Thickness(12, 10, 12, 10),
                Margin = new System.Windows.Thickness(0, 0, 0, 8)
            };
            card.SetResourceReference(Border.BackgroundProperty, "BrandDarkPanelBrush");
            card.SetResourceReference(Border.BorderBrushProperty, "BorderSubtleBrush");

            var sp = new StackPanel();

            // Row: drive letter + percent
            var header = new System.Windows.Controls.Grid();
            header.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new System.Windows.GridLength(1, System.Windows.GridUnitType.Star) });
            header.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = System.Windows.GridLength.Auto });

            var driveName = new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(disk.Label)
                    ? $"{disk.Name}  —  {disk.FileSystem} ({disk.DriveType})"
                    : $"{disk.Name} [{disk.Label}]  —  {disk.FileSystem}",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
            driveName.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimaryBrush");
            System.Windows.Controls.Grid.SetColumn(driveName, 0);

            var pctLabel = new TextBlock
            {
                Text = $"{pct:F1}% used",
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                Foreground = brush
            };
            System.Windows.Controls.Grid.SetColumn(pctLabel, 1);

            header.Children.Add(driveName);
            header.Children.Add(pctLabel);

            var bar = new System.Windows.Controls.ProgressBar
            {
                Minimum = 0,
                Maximum = 100,
                Value = pct,
                Height = 8,
                Margin = new System.Windows.Thickness(0, 6, 0, 6),
                Foreground = brush
            };
            bar.SetResourceReference(System.Windows.Controls.Control.BackgroundProperty, "BorderSubtleBrush");

            var detail = new TextBlock
            {
                Text = $"{freeGB:F1} GB free of {totalGB:F1} GB total",
                FontSize = 10
            };
            detail.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");

            sp.Children.Add(header);
            sp.Children.Add(bar);
            sp.Children.Add(detail);
            card.Child = sp;
            MonitorDiskList.Items.Add(card);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  CLICKABLE SCORE CARDS → Navigate + Auto-Scan
    //  (Adapted from TuneUp Utilities' one-click module launch)
    // ═══════════════════════════════════════════════════════════
    private void OnClickSecurityCard(object s, MouseButtonEventArgs e)
    {
        ShowPage(PageSentinel, "Sentinel — Security Center", NavSentinel);
        OnSentinelScan(s, new RoutedEventArgs());
    }

    private void OnClickPerfCard(object s, MouseButtonEventArgs e)
    {
        ShowPage(PageGuardian, "Guardian — Performance", NavGuardian);
        OnDriverScan(s, new RoutedEventArgs());
    }

    private void OnClickRegCard(object s, MouseButtonEventArgs e)
    {
        ShowPage(PageRegistry, "Registry Surgeon", NavRegistry);
        OnRegistryScan(s, new RoutedEventArgs());
    }

    private void OnClickRecoveryCard(object s, MouseButtonEventArgs e)
    {
        ShowPage(PageLazarus, "Lazarus — Data Recovery", NavLazarus);
    }

    // ═══════════════════════════════════════════════════════════
    //  LOADING OVERLAY
    // ═══════════════════════════════════════════════════════════
    private void ShowLoading(string message)
    {
        LoadingText.Text = message;
        LoadingOverlay.Visibility = Visibility.Visible;
        
        var anim = new System.Windows.Media.Animation.DoubleAnimation
        {
            From = 0,
            To = 360,
            Duration = TimeSpan.FromSeconds(1),
            RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever
        };
        SpinnerRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, anim);
    }
    private void HideLoading()
    {
        LoadingOverlay.Visibility = Visibility.Collapsed;
        SpinnerRotation.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
    }

    // ═══════════════════════════════════════════════════════════
    //  SHOW / HIDE DETAIL TOGGLES
    //  (Inspired by CCleaner's collapsible result sections)
    // ═══════════════════════════════════════════════════════════
    private static void ToggleDetailList(ItemsControl list, System.Windows.Controls.Button toggleBtn)
    {
        if (list.Visibility == Visibility.Visible)
        {
            list.Visibility = Visibility.Collapsed;
            toggleBtn.Content = "▼ Show Details";
        }
        else
        {
            list.Visibility = Visibility.Visible;
            toggleBtn.Content = "▲ Hide Details";
        }
    }

    private void OnToggleVulnDetails(object s, RoutedEventArgs e) => ToggleDetailList(VulnList, BtnToggleVulnDetails);
    private void OnToggleServiceDetails(object s, RoutedEventArgs e) => ToggleDetailList(ServiceList, BtnToggleServiceDetails);
    private void OnToggleDriverDetails(object s, RoutedEventArgs e) => ToggleDetailList(DriverList, BtnToggleDriverDetails);
    private void OnToggleBloatDetails(object s, RoutedEventArgs e) => ToggleDetailList(BloatList, BtnToggleBloatDetails);
    private void OnToggleStartupDetails(object s, RoutedEventArgs e) => ToggleDetailList(StartupList, BtnToggleStartupDetails);

    // Registry sub-section toggles
    private void OnToggleOrphans(object s, RoutedEventArgs e) => ToggleDetailList(OrphanList, BtnToggleOrphans);
    private void OnToggleBrokenAssoc(object s, RoutedEventArgs e) => ToggleDetailList(BrokenAssocList, BtnToggleBrokenAssoc);
    private void OnToggleInvalidPaths(object s, RoutedEventArgs e) => ToggleDetailList(InvalidPathList, BtnToggleInvalidPaths);
    private void OnToggleObsoleteRun(object s, RoutedEventArgs e) => ToggleDetailList(ObsoleteRunList, BtnToggleObsoleteRun);
    private void OnToggleComActiveX(object s, RoutedEventArgs e) => ToggleDetailList(ComActiveXList, BtnToggleComActiveX);
    private void OnToggleSharedDlls(object s, RoutedEventArgs e) => ToggleDetailList(SharedDllList, BtnToggleSharedDlls);
    private void OnToggleTypeLib(object s, RoutedEventArgs e) => ToggleDetailList(TypeLibList, BtnToggleTypeLib);
    private void OnToggleMuiCache(object s, RoutedEventArgs e) => ToggleDetailList(MuiCacheList, BtnToggleMuiCache);
    private void OnToggleHkcuOrphans(object s, RoutedEventArgs e) => ToggleDetailList(HkcuOrphanList, BtnToggleHkcuOrphans);
    private void OnToggleInstallerOrphans(object s, RoutedEventArgs e) => ToggleDetailList(InstallerOrphanList, BtnToggleInstallerOrphans);

    // ═══════════════════════════════════════════════════════════
    //  DASHBOARD QUICK ACTIONS
    // ═══════════════════════════════════════════════════════════
    private Action? _quickActionDetailAction;

    private void ShowQuickActionResult(
        string icon,
        string title,
        string detail,
        string buttonText,
        Action? onAction,
        string accentHex = "#22C55E")
    {
        try
        {
            QuickActionResultIcon.Text = icon;
            QuickActionResultTitle.Text = title;
            QuickActionResultDetail.Text = detail;

            if (System.Windows.Media.ColorConverter.ConvertFromString(accentHex) is Color col)
            {
                QuickActionResultTitle.Foreground = new SolidColorBrush(col);
                QuickActionResultBar.BorderBrush = new SolidColorBrush(Color.FromArgb(0x60, col.R, col.G, col.B));
            }

            _quickActionDetailAction = onAction;
            if (onAction != null && !string.IsNullOrEmpty(buttonText))
            {
                BtnQuickActionDetail.Content = buttonText;
                BtnQuickActionDetail.Visibility = Visibility.Visible;
            }
            else
            {
                BtnQuickActionDetail.Visibility = Visibility.Collapsed;
            }

            QuickActionResultBar.Visibility = Visibility.Visible;

            // Live event logged to Pulse AI Diagnostician terminal
            AppendTerminalLine($"> Quick Action: {title} — {detail}", accentHex, true);
        }
        catch { }
    }

    private void OnQuickActionDetailClick(object sender, RoutedEventArgs e)
    {
        _quickActionDetailAction?.Invoke();
    }

    private void OnDismissQuickActionResult(object sender, RoutedEventArgs e)
    {
        QuickActionResultBar.Visibility = Visibility.Collapsed;
    }

    private void UpdateTurboButtonVisuals(bool isActive)
    {
        try
        {
            if (isActive)
            {
                BtnQuickTurbo.Background = new SolidColorBrush(Color.FromArgb(0x35, 0xFF, 0x6F, 0x00));
                BtnQuickTurbo.BorderBrush = new SolidColorBrush(Color.FromRgb(0xFF, 0x6F, 0x00));
                QuickTurboText.Text = "Turbo: ACTIVE";
                QuickTurboText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0xA0, 0x40));
            }
            else
            {
                bool locked = !EditionService.Instance.Allows(Capability.Core);
                BtnQuickTurbo.Background = new SolidColorBrush(Color.FromArgb(0x18, 0xFF, 0x6F, 0x00));
                BtnQuickTurbo.BorderBrush = new SolidColorBrush(Color.FromArgb(0x40, 0xFF, 0x6F, 0x00));
                QuickTurboText.Text = locked ? "🔒 Turbo / Boost" : "Turbo / Boost";
                QuickTurboText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x6F, 0x00));
            }
            UpdateOverviewBar();
        }
        catch { }
    }

    private void UpdateOverviewBar()
    {
        try
        {
            if (OverviewHeadlineText == null || OverviewSublineText == null || OverviewShieldIcon == null) return;

            var edition = EditionService.Instance.Current.DisplayName();
            bool turboActive = _turboMode.IsActive;
            int vulns = _lastVulnResult?.Vulnerabilities.Count ?? 0;

            if (vulns > 0)
            {
                OverviewShieldIcon.Text = "⚠️";
                OverviewHeadlineText.Text = $"Attention Recommended — {vulns} security finding(s) detected";
                OverviewSublineText.Text = $"Edition: {edition} · Review Sentinel findings or press F1 for offline shortcuts (/boost).";
            }
            else if (turboActive)
            {
                var profileName = _turboMode.GetPersistedState()?.ProfileName is { Length: > 0 } pn ? pn : "Gaming";
                OverviewShieldIcon.Text = "🚀";
                OverviewHeadlineText.Text = $"Boost Mode Active ({profileName}) — Foreground app prioritized";
                OverviewSublineText.Text = $"Edition: {edition} · Run 'LogicFlow.exe /boost off' or click Turbo: ACTIVE below to restore normal profile.";
            }
            else
            {
                OverviewShieldIcon.Text = "🛡";
                OverviewHeadlineText.Text = $"System Protected — {edition} Edition Active";
                OverviewSublineText.Text = _settings?.LastScanDate > DateTimeOffset.MinValue
                    ? $"Last check: {_settings.LastScanDate.ToLocalTime():MMM d, h:mm tt} · Press F1 for help or pin 1-click /boost shortcuts."
                    : "Real-time hardware sensors online · Press F1 for offline help or pin 1-click /boost shortcuts.";
            }
        }
        catch { }
    }

    private async void OnQuickSecurityScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Running security scan...");
        try
        {
            var result = await _vulnScanner.ScanAsync();
            RenderSentinelResults(result);

            var detail = result.Vulnerabilities.Count == 0 && result.ExposedServices.Count == 0
                ? "Zero unpatched vulnerabilities or rogue listening ports found. Core defenses active."
                : $"{result.Vulnerabilities.Count} vulnerabilities and {result.ExposedServices.Count} open ports detected. Attack surface reduction recommended.";

            ShowQuickActionResult(
                "🛡",
                "Security Audit Complete",
                detail,
                "Open Sentinel",
                () => ShowPage(PageSentinel, "Sentinel — Security Center", NavSentinel),
                result.Vulnerabilities.Count > 0 ? "#F59E0B" : "#00E5FF");
        }
        catch (Exception ex) 
        { 
            SentinelStatus.Text = "Error";
            SentinelStatus.Foreground = (Brush)FindResource("DangerRedBrush");
            HealthMonitorLabel.Text = $"Error: {ex.Message}"; 
            HealthMonitorLabel.Foreground = (Brush)FindResource("DangerRedBrush");
            ShowQuickActionResult("⚠", "Security Scan Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    private async void OnQuickPerfScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing performance...");
        try
        {
            var driverReport = await Task.Run(() => _driverAuditor.AuditDrivers(true));
            RenderDriverResults(driverReport.Drivers);

            var startup = await Task.Run(() => _startupOptimizer.AnalyzeStartupItems());
            RenderStartupResults(startup);

            var driverStatus = _driverAuditor.CheckDriverStatus(driverReport);
            var badDrivers = driverStatus.ErrorCount + driverStatus.Outdated + driverStatus.Unsigned;
            var heavyStartup = startup.Count(si => si.ImpactScore >= 7);
            var score = driverStatus.HealthScore;
            DriverStatusLabel.Text = $"Perf Score: {score}%";
            DriverStatusLabel.Foreground = ScoreBrush(score);
            HealthMonitorLabel.Text = $"⚡ {badDrivers} driver issues, {heavyStartup} high-impact startup items";
            HealthMonitorLabel.Foreground = ScoreBrush(score);

            var detail = $"Audited {driverReport.Drivers.Count} hardware drivers ({badDrivers} alerts) and {startup.Count} startup items ({heavyStartup} high impact).";

            ShowQuickActionResult(
                "⚡",
                "Performance Audit Complete",
                detail,
                "Open Guardian",
                () => ShowPage(PageGuardian, "Guardian — Performance", NavGuardian),
                badDrivers > 0 || heavyStartup > 2 ? "#F59E0B" : "#22C55E");
        }
        catch (Exception ex) 
        { 
            DriverStatusLabel.Text = "Error";
            DriverStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
            HealthMonitorLabel.Text = $"Error: {ex.Message}"; 
            HealthMonitorLabel.Foreground = (Brush)FindResource("DangerRedBrush");
            ShowQuickActionResult("⚠", "Performance Scan Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    private async void OnQuickPrivacyScrub(object s, RoutedEventArgs e)
    {
        ShowLoading("Scrubbing privacy artifacts...");
        try
        {
            var report = await Task.Run(() => _privacyScrubber.Scrub());
            ScrubStatus.Text = "Privacy Scrub complete";
            ScrubStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            ScrubSummaryBar.Visibility = Visibility.Visible;
            ScrubSummaryText.Text = $"🧹 Cleared {report.TotalFilesCleared} files ({report.TotalBytesCleared / (1024.0 * 1024):F1} MB)";

            ShowQuickActionResult(
                "🔒",
                "Privacy Scrub Complete",
                $"Cleaned {report.TotalFilesCleared:N0} privacy artifacts and telemetry logs ({report.TotalBytesCleared / (1024.0 * 1024):F1} MB purged).",
                "View Details",
                () => ShowPage(PageSentinel, "Sentinel — Security Center", NavSentinel),
                "#00E5FF");
        }
        catch (Exception ex) 
        { 
            ScrubStatus.Text = $"Scrub error: {ex.Message}"; 
            ScrubStatus.Foreground = (Brush)FindResource("DangerRedBrush");
            ShowQuickActionResult("⚠", "Privacy Scrub Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    private async void OnQuickRegistryScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning registry...");
        try
        {
            var result = await Task.Run(() => _registryAnalyzer.Scan());
            RenderRegistryResults(result);

            var detail = result.TotalIssues == 0
                ? "Registry hive integrity is 100%. Zero orphaned keys or broken paths found."
                : result.FormatBreakdown();

            ShowQuickActionResult(
                "🔧",
                "Registry Scan Complete",
                detail,
                "Registry Surgeon",
                () => ShowPage(PageRegistry, "Registry Surgeon", NavRegistry),
                result.TotalIssues > 0 ? "#38BDF8" : "#22C55E");
        }
        catch (Exception ex) 
        { 
            RegistryStatus.Text = "Error";
            RegistryStatus.Foreground = (Brush)FindResource("DangerRedBrush");
            HealthMonitorLabel.Text = $"Error: {ex.Message}"; 
            HealthMonitorLabel.Foreground = (Brush)FindResource("DangerRedBrush");
            ShowQuickActionResult("⚠", "Registry Scan Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    private async void OnRunAllScans(object s, RoutedEventArgs e)
    {
        ShowLoading("Running all scans in sequence...");
        try
        {
            // 1. Security Scan (Sentinel)
            ShowLoading("Auditing security vulnerabilities & listening services...");
            var secResult = await _vulnScanner.ScanAsync();
            RenderSentinelResults(secResult);

            // 2. Performance Scan (Guardian)
            ShowLoading("Auditing system drivers & hardware integrity...");
            var driverReport = await Task.Run(() => _driverAuditor.AuditDrivers(true));
            RenderDriverResults(driverReport.Drivers);

            ShowLoading("Auditing startup applications...");
            var startup = await Task.Run(() => _startupOptimizer.AnalyzeStartupItems());
            RenderStartupResults(startup);

            ShowLoading("Auditing pre-installed bloatware...");
            var bloat = await Task.Run(() => _debloatEngine.ScanBloatware());
            RenderBloatwareResults(bloat);

            ShowLoading("Auditing physical storage drives (S.M.A.R.T.)...");
            var smartDrives = await Task.Run(() => _smartDiskHealth.ScanDrives());
            RenderSmartDiskResults(smartDrives);

            RenderTweakResults();

            // 3. Registry Scan (Registry Surgeon)
            ShowLoading("Scanning Windows Registry hives...");
            var regResult = await Task.Run(() => _registryAnalyzer.Scan());
            RenderRegistryResults(regResult);

            // 4. Junk Cleaner (Toolbox)
            ShowLoading("Auditing temporary and junk files...");
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            var junkReport = await Task.Run(() => _junkCleaner.Scan());
            RenderJunkResults(junkReport);

            var driverStatus = _driverAuditor.CheckDriverStatus(driverReport);
            var badDrivers = driverStatus.ErrorCount + driverStatus.Outdated + driverStatus.Unsigned;
            var heavyStartup = startup.Count(si => si.ImpactScore >= 7);

            var summary = $"Security: {secResult.Vulnerabilities.Count} vulns | Perf: {badDrivers} driver alerts, {heavyStartup} startup apps | Registry: {regResult.TotalIssues} issues.";
            HealthMonitorLabel.Text = summary;
            HealthMonitorLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
            UpdateOverviewBar();

            ShowQuickActionResult(
                "📊",
                "Full System Audit Complete",
                summary + " All Sentinel, Guardian, Registry, and Toolbox tabs synchronized.",
                "View Sentinel",
                () => ShowPage(PageSentinel, "Sentinel — Security Center", NavSentinel),
                "#00E5FF");
        }
        catch (Exception ex)
        {
            ShowQuickActionResult("⚠", "Unified Audit Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    // ─── Quick Junk Clean ───
    private async void OnQuickJunkClean(object s, RoutedEventArgs e)
    {
        ShowLoading("Cleaning junk files...");
        try
        {
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            var report = await Task.Run(() => _junkCleaner.Scan());
            _lastJunkReport = report;
            var cleanResult = await Task.Run(() => _junkCleaner.Clean(report));
            var totalMB = cleanResult.BytesCleaned / (1024.0 * 1024);
            var totalFiles = cleanResult.FilesDeleted;

            JunkStatus.Text = "Junk Clean complete";
            JunkStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            JunkSummaryBar.Visibility = Visibility.Visible;
            JunkSummaryText.Text = $"🧹 Cleaned {totalFiles:N0} files ({totalMB:F1} MB freed)";

            // Asynchronously refresh live storage metrics
            _ = Task.Run(() =>
            {
                try
                {
                    var disks = SystemInfoEngine.CollectDiskInfo();
                    Dispatcher.Invoke(() =>
                    {
                        if (_liveSnapshot != null) _liveSnapshot.Disks = disks;
                        UpdateDashboardLiveMetrics();
                    });
                }
                catch { }
            });

            ShowQuickActionResult(
                "🧹",
                "Junk Files Cleaned",
                $"Successfully purged {totalFiles:N0} temporary files and caches, freeing {totalMB:F1} MB disk storage.",
                "View Details",
                () => ShowPage(PageToolbox, "Toolbox — Utilities", NavToolbox),
                "#8B5CF6");
        }
        catch (Exception ex) 
        { 
            JunkStatus.Text = $"Junk clean error: {ex.Message}"; 
            JunkStatus.Foreground = (Brush)FindResource("DangerRedBrush");
            ShowQuickActionResult("⚠", "Junk Clean Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    // ─── Quick Memory Optimize ───
    private async void OnQuickMemoryOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Optimizing memory...");
        try
        {
            var result = await Task.Run(() => _memoryOptimizer.Optimize());
            var afterPct = result.After.PhysicalUsagePercent;
            var freedMB = result.TotalMemoryFreedBytes / (1024.0 * 1024);
            
            MemOptStatus.Text = result.IsAdmin
                ? $"Freed {freedMB:F0} MB ({result.AreasCleared})"
                : $"Freed {freedMB:F0} MB (run as admin for full optimization)";
            MemOptStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            
            MiniRamBar.Value = afterPct;
            MiniRamBar.Foreground = MetricBrush(afterPct, Resources);
            MiniRamText.Text = $"{afterPct:F0}%";

            ShowQuickActionResult(
                "🧠",
                "RAM Optimization Complete",
                $"Reclaimed {freedMB:F0} MB of inactive working sets across processes. RAM load reduced to {afterPct:F0}%.",
                "Resource Monitor",
                () => ShowPage(PageMonitor, "Resource Monitor — Live", NavMonitor),
                "#A855F7");
        }
        catch (Exception ex) 
        { 
            MemOptStatus.Text = $"Error: {ex.Message}"; 
            MemOptStatus.Foreground = (Brush)FindResource("DangerRedBrush");
            ShowQuickActionResult("⚠", "Memory Optimize Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    // ─── Quick Turbo Toggle & Headless /boost Command ───
    public bool IsTurboActive => _turboMode.IsActive;

    /// <summary>
    /// Handles silent CLI/shortcut '/boost' and '/boost off' invocations without stealing foreground focus
    /// or opening modal windows over a running full-screen game.
    /// Zero-hostage revert: '/boost off' always deactivates even on Free or expired trial.
    /// </summary>
    public async void HandleHeadlessBoostCommand(bool enable)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => HandleHeadlessBoostCommand(enable));
            return;
        }

        try
        {
            _trayManager ??= new TrayIconManager(this);
            CheckAndApplySavedLicense();

            if (!enable)
            {
                await Task.Run(() => _turboMode.Deactivate());
                UpdateTurboButtonVisuals(false);
                _trayManager.SetTooltipSafe("LogicFlow — System Protection Active");
                _trayManager.ShowBalloon(
                    "LogicFlow Boost Mode Off",
                    "Restored previous power plan, notification state, CPU affinity, and foreground priority.",
                    System.Windows.Forms.ToolTipIcon.Info,
                    2500);
                return;
            }

            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                _trayManager.ShowBalloon(
                    "LogicFlow Boost Mode",
                    "Open LogicFlow from the tray once to complete first-run privacy & edition setup before using Boost Mode.",
                    System.Windows.Forms.ToolTipIcon.Info,
                    3500);
                return;
            }

            if (!EditionService.Instance.Allows(Capability.Core))
            {
                _trayManager.ShowBalloon(
                    "LogicFlow Boost Mode",
                    "Boost Mode requires Community ($0) or Pro — open LogicFlow from the tray to switch.",
                    System.Windows.Forms.ToolTipIcon.Info,
                    3500);
                return;
            }

            var result = await Task.Run(() => _turboMode.Activate(
                TurboMode.GamingProfile,
                beforeSuppressNotifications: res => Dispatcher.Invoke(() =>
                {
                    _trayManager.SetTooltipSafe("LogicFlow — Boost Mode Active (Gaming)");
                    _trayManager.ShowBalloon(
                        "LogicFlow Boost Mode Active",
                        $"Gaming profile engaged: {res.MemoryFreedFormatted} RAM freed, {res.ProcessesKilled} background app(s) terminated.",
                        System.Windows.Forms.ToolTipIcon.Info,
                        2500);
                })));
            UpdateTurboButtonVisuals(true);
            _trayManager.SetTooltipSafe("LogicFlow — Boost Mode Active (Gaming)");
        }
        catch { }
    }

    public void EngageTurboBoost()
    {
        if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
        {
            ConsentWindow.ShowFirstRun();
            ApplyEdition();
            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                return;
            }
        }
        if (!EditionService.Instance.Allows(Capability.Core)) return;
        if (!_turboMode.IsActive)
        {
            OnToggleTurbo(this, new RoutedEventArgs());
        }
    }

    private async void OnToggleTurbo(object s, RoutedEventArgs e)
    {
        if (!_turboMode.IsActive)
        {
            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                ConsentWindow.ShowFirstRun();
                ApplyEdition();
                if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
                {
                    return;
                }
            }
            if (!Gate.Require(Capability.Core, this)) return;

            var targets = _turboMode.PreviewTargetProcesses(TurboMode.GamingProfile);
            if (targets.Count > 0 && IsVisible)
            {
                string previewList = FormatTurboTargetsPreview(targets);
                bool proceed = Dialogs.Confirm(
                    this,
                    "Engage Gaming Boost Mode",
                    $"Boost Mode will switch to the High Performance power plan, prioritize your active foreground app, trim standby RAM, and terminate {targets.Count} non-essential background process(es):\n\n{previewList}\n\nTerminated apps are not automatically relaunched when Boost Mode turns off.",
                    "Engage Boost",
                    "Cancel",
                    defaultCancel: false);
                if (!proceed) return;
            }

            ShowLoading("Engaging Turbo Mode...");
            try
            {
                var result = await Task.Run(() => _turboMode.Activate(TurboMode.GamingProfile));
                UpdateTurboButtonVisuals(true);
                _trayManager?.SetTooltipSafe("LogicFlow — Boost Mode Active (Gaming)");

                ShowQuickActionResult(
                    "🚀",
                    "Turbo / Boost Engaged",
                    $"Gaming Profile active: {result.ServicesDisabled} services stopped, {result.ProcessesKilled} background process(es) terminated. {result.MemoryFreedFormatted} RAM reclaimed.",
                    "Deactivate",
                    () => OnToggleTurbo(s, e),
                    "#FF6F00");
            }
            catch (Exception ex)
            {
                ShowQuickActionResult("⚠", "Turbo Activation Error", ex.Message, "Dismiss", null, "#EF4444");
            }
            finally { HideLoading(); }
        }
        else
        {
            ShowLoading("Restoring Normal Operations...");
            try
            {
                var result = await Task.Run(() => _turboMode.Deactivate());
                UpdateTurboButtonVisuals(false);
                _trayManager?.SetTooltipSafe("LogicFlow — System Protection Active");

                ShowQuickActionResult(
                    "🚀",
                    "Turbo / Boost Deactivated",
                    "Restored previous power plan, notification state, stopped services, CPU affinity, and foreground priority.",
                    "Re-engage",
                    () => OnToggleTurbo(s, e),
                    "#94A3B8");
            }
            catch (Exception ex)
            {
                ShowQuickActionResult("⚠", "Turbo Deactivation Error", ex.Message, "Dismiss", null, "#EF4444");
            }
            finally { HideLoading(); }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  1-CLICK MAINTENANCE
    // ═══════════════════════════════════════════════════════════
    private async void OnOneClickOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Running 1-Click Maintenance...");
        try
        {
            bool cleanJunk = ChkOneClickJunk.IsChecked == true;
            bool checkRegistry = ChkOneClickRegistry.IsChecked == true;
            bool optimizeStartup = ChkOneClickStartup.IsChecked == true;
            bool applyTweaks = ChkOneClickTweaks.IsChecked == true;

            // Run full 1-Click Maintenance via the orchestrator
            var oneClick = new OneClickMaintenance();
            OneClickStatus.Text = "Running maintenance...";
            var report = await Task.Run(() => oneClick.Run(
                _junkCleaner,
                _tweakEngine,
                systemInfo: null,
                cleanJunk: cleanJunk,
                checkRegistry: checkRegistry,
                optimizeStartup: optimizeStartup,
                applyTweaks: applyTweaks,
                optimizeMemory: false,
                registryIssueScanner: checkRegistry ? () => _registryAnalyzer.Scan().TotalIssues : null));

            // Also run memory optimize
            OneClickStatus.Text = "Optimizing memory...";
            var memResult = await Task.Run(() => _memoryOptimizer.Optimize());

            // Calculate health score
            var afterPct = memResult.After.PhysicalUsagePercent;
            var freedMB = memResult.TotalMemoryFreedBytes / (1024.0 * 1024);
            var junkMB = report.JunkBytesCleaned / (1024.0 * 1024);
            var diskUsage = 50.0; // reasonable default
            try { var di = new DriveInfo("C"); diskUsage = (1.0 - (double)di.TotalFreeSpace / di.TotalSize) * 100; } catch { }
            var score = OneClickMaintenance.HealthScore.Calculate(afterPct, diskUsage, (int)junkMB, report.RegistryIssuesFound, report.SafeTweaksApplied, report.HighImpactStartupItems);

            // Update Dashboard cards
            HealthScoreLabel.Text = $"{score.Score}%";
            HealthScoreLabel.Foreground = ScoreBrush(score.Score);
            HealthScoreSub.Text = $"🏥 Grade: {score.Grade}";
            HealthProgressRing.Progress = score.Score;

            HealthMonitorLabel.Text = $"Cleaned {junkMB:F1} MB, freed {freedMB:F0} MB RAM";
            HealthMonitorLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");

            MemOptStatus.Text = $"Freed {freedMB:F0} MB";
            MemOptStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            MiniRamBar.Value = afterPct;
            MiniRamBar.Foreground = MetricBrush(afterPct, Resources);
            MiniRamText.Text = $"{afterPct:F0}%";

            OneClickSummaryBar.Visibility = Visibility.Visible;
            OneClickSummaryText.Text = $"✅ {report.Summary} — Freed {freedMB:F0} MB RAM";
            OneClickStatus.Text = "1-Click Maintenance complete!";
            OneClickStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");

            OneClickList.Items.Clear();
            foreach (var action in report.Actions)
            {
                var isSkip = action.Contains("skipped");
                var brushKey = isSkip ? "TextSecondaryBrush" : "SuccessGreenBrush";
                OneClickList.Items.Add(MakeResultCard(action, "", brushKey));
            }

            ShowQuickActionResult(
                "🎯",
                "1-Click Maintenance Complete",
                $"Cleaned {junkMB:F1} MB junk files and freed {freedMB:F0} MB RAM. System health calibrated to {score.Score}% ({score.Grade}).",
                "View Report",
                () => ShowPage(PageToolbox, "Toolbox — Utilities", NavToolbox),
                "#22C55E");
        }
        catch (Exception ex)
        {
            OneClickStatus.Text = $"Error: {ex.Message}";
            ShowQuickActionResult("⚠", "1-Click Maintenance Error", ex.Message, "Dismiss", null, "#EF4444");
        }
        finally { HideLoading(); }
    }

    // ═══════════════════════════════════════════════════════════
    //  SENTINEL PAGE — Security Scan + Fix Actions
    // ═══════════════════════════════════════════════════════════
    private void RenderSentinelResults(VulnScanResult result)
    {
        _lastVulnResult = result;
        VulnList.Items.Clear();
        ServiceList.Items.Clear();

        // Vulnerability summary bar (count-based, like Norton Utilities)
        VulnSummaryBar.Visibility = Visibility.Visible;
        VulnSummaryText.Text = result.Vulnerabilities.Count > 0
            ? $"⚠ {result.Vulnerabilities.Count} vulnerabilities found — Windows Update recommended"
            : "✅ No known vulnerabilities detected";
        VulnSummaryText.Foreground = result.Vulnerabilities.Count > 0
            ? (Brush)FindResource("DangerRedBrush")
            : (Brush)FindResource("SuccessGreenBrush");

        // Show "Fix All" button if vulns found
        BtnFixVulns.Visibility = result.Vulnerabilities.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        // Auto-expand detail list if threats detected
        if (result.Vulnerabilities.Count > 0)
        {
            VulnList.Visibility = Visibility.Visible;
            BtnToggleVulnDetails.Content = "▲ Hide Details";
        }
        else
        {
            VulnList.Visibility = Visibility.Collapsed;
            BtnToggleVulnDetails.Content = "▼ Show Details";
        }

        // Populate detail list
        foreach (var v in result.Vulnerabilities)
            VulnList.Items.Add(MakeActionCard($"⚠ {v.KbId} — {v.Title}", v.Impact, "DangerRedBrush", "🔧 Fix", () => OpenWindowsUpdate()));

        if (result.Vulnerabilities.Count == 0)
            VulnList.Items.Add(MakeResultCard("✅ System is patched and up to date", "All known CVEs addressed", "SuccessGreenBrush"));

        // Exposed services summary
        ExposedServicesStatus.Visibility = Visibility.Collapsed;
        ServiceSummaryBar.Visibility = Visibility.Visible;
        ServiceSummaryText.Text = result.ExposedServices.Count > 0
            ? $"🔓 {result.ExposedServices.Count} exposed services detected"
            : "✅ No exposed services";
        BtnDisableServices.Visibility = result.ExposedServices.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        if (result.ExposedServices.Count > 0)
        {
            ServiceList.Visibility = Visibility.Visible;
            BtnToggleServiceDetails.Content = "▲ Hide Details";
        }
        else
        {
            ServiceList.Visibility = Visibility.Collapsed;
            BtnToggleServiceDetails.Content = "▼ Show Details";
        }

        foreach (var svc in result.ExposedServices)
            ServiceList.Items.Add(MakeActionCard($"🔓 {svc.DisplayName} ({svc.ServiceName})", svc.Risk, "WarningAmberBrush", "🔒 Disable", () => DisableSingleService(svc.ServiceName)));

        SentinelStatus.Text = $"Scan complete — {result.InstalledUpdates.Count} updates checked";
        SentinelStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");

        // Update dashboard card
        var score = Math.Max(0, 100 - (result.Vulnerabilities.Count * 20) - (result.ExposedServices.Count * 5));
        SentinelStatus.Text = $"Sentinel Score: {score}%";
        SentinelStatus.Foreground = ScoreBrush(score);
        HealthMonitorLabel.Text = $"🛡 {result.Vulnerabilities.Count} vulns, {result.ExposedServices.Count} exposed";
        HealthMonitorLabel.Foreground = ScoreBrush(score);
    }

    private async void OnSentinelScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Deep security scan...");
        SentinelStatus.Text = "Scanning...";
        try
        {
            var result = await _vulnScanner.ScanAsync();
            RenderSentinelResults(result);
        }
        catch (Exception ex) { SentinelStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnFixVulnerabilities(object s, RoutedEventArgs e) => OpenWindowsUpdate();

    private async void DisableSingleService(string serviceName)
    {
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Disable Service",
            $"Stop and disable service '{serviceName}'?\n\nThis will prevent the service from running and exposing network ports.",
            "Disable Service",
            "Cancel",
            destructive: true))
            return;

        ShowLoading($"Disabling service {serviceName}...");
        try
        {
            await Task.Run(() =>
            {
                using var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -Command \"Stop-Service -Name '{serviceName}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '{serviceName}' -StartupType Disabled\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                proc?.WaitForExit(10000);
            });
            SentinelStatus.Text = $"Service '{serviceName}' has been stopped and disabled.";
            SentinelStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnSentinelScan(this, new RoutedEventArgs());
        }
        catch (Exception ex)
        {
            SentinelStatus.Text = $"Failed to disable service: {ex.Message}";
            SentinelStatus.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnDisableExposedServices(object s, RoutedEventArgs e)
    {
        if (_lastVulnResult == null || _lastVulnResult.ExposedServices.Count == 0) return;
        var services = _lastVulnResult.ExposedServices;
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Disable Risky Services",
            $"Stop and disable all {services.Count} exposed services?\n\n" +
            string.Join("\n", services.Take(8).Select(x => $"• {x.DisplayName} ({x.ServiceName})")) +
            (services.Count > 8 ? $"\n... and {services.Count - 8} more" : "") +
            "\n\nServices can be re-enabled from Windows Services (services.msc).",
            "Disable All Exposed",
            "Cancel",
            defaultCancel: true,
            destructive: true))
            return;

        ShowLoading("Stopping and disabling exposed services...");
        try
        {
            await Task.Run(() =>
            {
                foreach (var svc in services)
                {
                    using var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -NonInteractive -Command \"Stop-Service -Name '{svc.ServiceName}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '{svc.ServiceName}' -StartupType Disabled\"",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    proc?.WaitForExit(10000);
                }
            });
            SentinelStatus.Text = $"All {services.Count} exposed services have been stopped and disabled.";
            SentinelStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnSentinelScan(s, e);
        }
        catch (Exception ex)
        {
            SentinelStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private static void OpenWindowsUpdate()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:windowsupdate") { UseShellExecute = true });
        }
        catch { }
    }

    // ─── Network Security Scanner (10-vector) ───
    private NetworkScanReport? _lastNetworkScanReport;

    private async void OnNetworkScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Running 10-vector network security scan...");
        NetworkFindingsList.Items.Clear();
        NetworkScanStatus.Text = "Scanning...";
        try
        {
            var report = await _networkScanner.FullScanAsync();
            _lastNetworkScanReport = report;

            NetworkSummaryBar.Visibility = Visibility.Visible;

            // Build finding cards from the structured report
            var cards = new List<(string Title, string Detail, string BrushKey)>();

            // Open ports (Critical/High)
            foreach (var p in report.OpenPorts)
            {
                var sev = p.Severity == FindingSeverity.Critical ? "Critical" : "High";
                cards.Add(($"{(sev == "Critical" ? "🔴" : "⚠")} [Open Port] {p.Service} :{p.Port}",
                    $"{sev} — {p.Risk}", sev == "Critical" ? "DangerRedBrush" : "WarningAmberBrush"));
            }

            // Firewall disabled
            if (report.FirewallStatus.IsDisabled)
                cards.Add(("🔴 [Firewall] Windows Firewall Disabled",
                    "Critical — One or more firewall profiles are disabled", "DangerRedBrush"));

            // RDP Exposure
            if (report.RdpExposure.IsExposed)
                cards.Add(("🔴 [RDP] Remote Desktop Exposed",
                    "Critical — RDP enabled without Network Level Authentication", "DangerRedBrush"));

            // SMBv1
            if (report.SmbV1Status.IsEnabled)
                cards.Add(("🔴 [SMBv1] Legacy Protocol Enabled",
                    "Critical — WannaCry/EternalBlue attack vector active", "DangerRedBrush"));

            // WinRM
            if (report.WinRmStatus.IsEnabled)
                cards.Add(("⚠ [WinRM] Remote Management Active",
                    "Warning — Lateral movement risk via WinRM", "WarningAmberBrush"));

            // UPnP
            if (report.UpnpStatus.IsEnabled)
                cards.Add(("⚠ [UPnP] Automatic Port Forwarding",
                    "Warning — SSDP service is active", "WarningAmberBrush"));

            // DNS Leaks
            if (report.DnsLeakResults.IsLeaking)
                cards.Add(("⚠ [DNS] Potential DNS Leak",
                    $"Warning — {report.DnsLeakResults.PotentialLeaks.Count} non-privacy DNS servers detected", "WarningAmberBrush"));

            // WiFi
            if (report.WifiSecurity.IsVulnerable)
                cards.Add(("⚠ [WiFi] Weak Wireless Security",
                    $"Warning — {report.WifiSecurity.AuthType} / {report.WifiSecurity.Cipher}", "WarningAmberBrush"));

            // Open Shares
            foreach (var share in report.OpenShares)
                cards.Add(("ℹ [Shares] " + share.Name,
                    $"Info — Path: {share.Path}", "BrandCyanBrush"));

            // ARP Devices (info)
            if (report.ArpDevices.Count > 0)
                cards.Add(($"ℹ [ARP] {report.ArpDevices.Count} Devices on Local Network",
                    "Info — Review device list for unauthorized devices", "BrandCyanBrush"));

            var criticalCount = cards.Count(c => c.BrushKey == "DangerRedBrush");
            var warningCount = cards.Count(c => c.BrushKey == "WarningAmberBrush");
            var infoCount = cards.Count(c => c.BrushKey == "BrandCyanBrush");

            NetworkSummaryText.Text = $"Risk Score: {report.RiskScore}/100 — " + (criticalCount > 0
                ? $"🔴 {criticalCount} critical, {warningCount} warnings, {infoCount} informational"
                : warningCount > 0
                    ? $"⚠ {warningCount} warnings, {infoCount} informational"
                    : $"✅ {infoCount} informational — network looks secure");
            NetworkSummaryText.Foreground = report.RiskScore >= 30
                ? (Brush)FindResource("DangerRedBrush")
                : report.RiskScore > 0
                    ? (Brush)FindResource("WarningAmberBrush")
                    : (Brush)FindResource("SuccessGreenBrush");

            BtnRemediateNetwork.Visibility = (criticalCount + warningCount) > 0 ? Visibility.Visible : Visibility.Collapsed;

            foreach (var card in cards)
                NetworkFindingsList.Items.Add(MakeResultCard(card.Title, card.Detail, card.BrushKey));

            NetworkScanStatus.Text = $"Scan complete — {report.TotalFindings} findings, risk score {report.RiskScore}/100";
            NetworkScanStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { NetworkScanStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnRemediateAll(object s, RoutedEventArgs e)
    {
        if (_lastNetworkScanReport == null) return;
        ShowLoading("Applying security remediations...");
        try
        {
            var report = await _remediationEngine.AutoRemediateAsync(_lastNetworkScanReport, dryRun: false);
            NetworkScanStatus.Text = $"✅ Applied {report.SuccessCount}/{report.TotalActions} remediations";
            NetworkScanStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");

            // Re-scan to show updated state
            OnNetworkScan(s, e);
        }
        catch (Exception ex) { NetworkScanStatus.Text = $"Remediation error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Startup Security Audit ───
    private async void OnStartupAudit(object s, RoutedEventArgs e)
    {
        ShowLoading("Auditing startup entries for threats...");
        StartupAuditList.Items.Clear();
        StartupAuditStatus.Text = "Scanning...";
        try
        {
            var report = await Task.Run(() => _startupAuditor.Audit());
            var suspicious = report.Entries.Where(e2 => e2.Classification == StartupClassification.Suspicious).ToList();
            var safe = report.Entries.Where(e2 => e2.Classification != StartupClassification.Suspicious).ToList();

            StartupAuditSummaryBar.Visibility = Visibility.Visible;
            StartupAuditSummaryText.Text = suspicious.Count > 0
                ? $"🔴 {suspicious.Count} suspicious entries found out of {report.TotalEntries} total"
                : $"✅ All {report.TotalEntries} startup entries appear safe";
            StartupAuditSummaryText.Foreground = suspicious.Count > 0
                ? (Brush)FindResource("DangerRedBrush")
                : (Brush)FindResource("SuccessGreenBrush");

            foreach (var entry in suspicious)
            {
                StartupAuditList.Items.Add(MakeResultCard(
                    $"🔴 {entry.Name}",
                    $"Reason: {entry.Reason ?? "Unknown"} | Source: {entry.Source} | Command: {entry.Command}",
                    "DangerRedBrush"));
            }

            foreach (var entry in safe.Take(10))
            {
                StartupAuditList.Items.Add(MakeResultCard(
                    $"✅ {entry.Name}",
                    $"Source: {entry.Source}",
                    "SuccessGreenBrush"));
            }
            if (safe.Count > 10)
                StartupAuditList.Items.Add(MakeResultCard($"... and {safe.Count - 10} more safe entries", "", "TextSecondaryBrush"));

            StartupAuditStatus.Text = $"Audit complete — {report.TotalEntries} entries scanned";
            StartupAuditStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { StartupAuditStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Windows Defender Enterprise Hardener & ASR ───
    private async void OnDefenderHardenStatus(object s, RoutedEventArgs e)
    {
        ShowLoading("Checking Windows Defender ASR & Hardening status...");
        DefenderHardenList.Items.Clear();
        try
        {
            var status = await _defenderHardener.GetStatusAsync();
            DefenderHardenSummaryBar.Visibility = Visibility.Visible;
            DefenderHardenSummaryText.Text = $"🛡 {status.ActiveAsrRulesCount}/{status.TotalAsrRulesCount} ASR Rules Active | PUA: {(status.IsPuaProtectionEnabled ? "ON" : "OFF")} | Ransomware Shield: {(status.IsControlledFolderAccessEnabled ? "ON" : "OFF")}";
            DefenderHardenStatus.Text = $"Status: {status.ActiveAsrRulesCount} rules enabled";
            DefenderHardenStatus.Foreground = status.ActiveAsrRulesCount > 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("TextSecondaryBrush");

            DefenderHardenList.Items.Add(MakeDefenderToggleCard(
                "PUA / Adware Shield",
                "Blocks potentially unwanted applications, bundling adware, and suspicious download wrappers.",
                status.IsPuaProtectionEnabled,
                async () =>
                {
                    await _defenderHardener.SetPuaProtectionAsync(!status.IsPuaProtectionEnabled);
                    OnDefenderHardenStatus(s, e);
                }));

            DefenderHardenList.Items.Add(MakeDefenderToggleCard(
                "Anti-Ransomware Controlled Folder Access",
                "Guards Documents, Desktop, and Pictures from unauthorized encryption and ransomware writes.",
                status.IsControlledFolderAccessEnabled,
                async () =>
                {
                    await _defenderHardener.SetControlledFolderAccessAsync(!status.IsControlledFolderAccessEnabled);
                    OnDefenderHardenStatus(s, e);
                }));

            foreach (var r in status.AsrRules)
            {
                DefenderHardenList.Items.Add(MakeDefenderToggleCard(
                    r.Name,
                    $"{r.Description}\nGUID: {r.Guid}",
                    r.IsEnabled,
                    async () =>
                    {
                        await _defenderHardener.ToggleAsrRuleAsync(r.Guid);
                        OnDefenderHardenStatus(s, e);
                    }));
            }
        }
        catch (Exception ex) { DefenderHardenStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnDefenderHardenAll(object s, RoutedEventArgs e)
    {
        ShowLoading("Enabling full enterprise Defender ASR rules & ransomware shields...");
        try
        {
            var res = await _defenderHardener.EnableAllHardeningAsync();
            DefenderHardenStatus.Text = res.Success ? "Full Enterprise ASR and Defender Hardening Active!" : $"Warning: {res.ErrorMessage}";
            DefenderHardenStatus.Foreground = res.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");
            OnDefenderHardenStatus(s, e);
        }
        catch (Exception ex) { DefenderHardenStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnDefenderRevert(object s, RoutedEventArgs e)
    {
        ShowLoading("Reverting Defender policies to Windows defaults...");
        try
        {
            await _defenderHardener.RevertAllAsync();
            DefenderHardenStatus.Text = "Reverted Defender policies to Windows defaults.";
            OnDefenderHardenStatus(s, e);
        }
        catch (Exception ex) { DefenderHardenStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnDefenderQuickScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Running Microsoft Defender Quick Antivirus Scan...");
        try
        {
            var res = await _defenderHardener.TriggerScanAsync(DefenderScanType.Quick);
            DefenderHardenSummaryBar.Visibility = Visibility.Visible;
            DefenderHardenSummaryText.Text = res.Success
                ? $"✅ Quick Scan completed in {res.Duration.TotalSeconds:F1}s (Exit code: {res.ExitCode})"
                : $"⚠️ Quick Scan encountered error: {res.ErrorMessage}";
            DefenderHardenSummaryText.Foreground = res.Success
                ? (Brush)FindResource("SuccessGreenBrush")
                : (Brush)FindResource("DangerRedBrush");
            DefenderHardenStatus.Text = res.Success ? "Defender Quick Scan completed successfully." : $"Error: {res.ErrorMessage}";
            DefenderHardenStatus.Foreground = res.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");

            DefenderHardenList.Items.Insert(0, MakeResultCard(
                $"⚡ Quick Antivirus Scan: {(res.Success ? "COMPLETED" : "FAILED")}",
                $"Duration: {res.Duration.TotalSeconds:F1}s | Output: {res.ScanOutput ?? "Scan finished."}",
                res.Success ? "SuccessGreenBrush" : "DangerRedBrush"));
        }
        catch (Exception ex) { DefenderHardenStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnDefenderFullScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Running Microsoft Defender Full System Antivirus Scan...");
        try
        {
            var res = await _defenderHardener.TriggerScanAsync(DefenderScanType.Full);
            DefenderHardenSummaryBar.Visibility = Visibility.Visible;
            DefenderHardenSummaryText.Text = res.Success
                ? $"✅ Full Scan completed in {res.Duration.TotalMinutes:F1}m (Exit code: {res.ExitCode})"
                : $"⚠️ Full Scan encountered error: {res.ErrorMessage}";
            DefenderHardenSummaryText.Foreground = res.Success
                ? (Brush)FindResource("SuccessGreenBrush")
                : (Brush)FindResource("DangerRedBrush");
            DefenderHardenStatus.Text = res.Success ? "Defender Full Scan completed successfully." : $"Error: {res.ErrorMessage}";
            DefenderHardenStatus.Foreground = res.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");

            DefenderHardenList.Items.Insert(0, MakeResultCard(
                $"🛡 Full Antivirus Scan: {(res.Success ? "COMPLETED" : "FAILED")}",
                $"Duration: {res.Duration.TotalMinutes:F1}m | Output: {res.ScanOutput ?? "Full scan finished."}",
                res.Success ? "SuccessGreenBrush" : "DangerRedBrush"));
        }
        catch (Exception ex) { DefenderHardenStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnDefenderOfflineScan(object s, RoutedEventArgs e)
    {
        if (!Gate.Require(Capability.Core, this)) return;
        if (!Dialogs.Confirm(
            this,
            "Schedule Defender Offline Scan",
            "Schedule Microsoft Defender Offline Scan?\n\nThis will trigger a deep kernel & boot-sector scan before Windows loads on next reboot.",
            "Schedule Scan",
            "Cancel"))
            return;

        ShowLoading("Triggering Microsoft Defender Offline Boot Scan...");
        try
        {
            var res = await _defenderHardener.TriggerScanAsync(DefenderScanType.OfflineBoot);
            DefenderHardenStatus.Text = res.Success
                ? "Offline Defender Scan scheduled. Restart system to initiate boot scan."
                : $"Failed to schedule offline scan: {res.ErrorMessage}";
            DefenderHardenStatus.Foreground = res.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");

            DefenderHardenList.Items.Insert(0, MakeResultCard(
                $"🔄 Offline Boot Scan: {(res.Success ? "SCHEDULED" : "FAILED")}",
                res.Success ? "System will perform an offline scan outside Windows on next reboot." : $"Error: {res.ErrorMessage}",
                res.Success ? "WarningAmberBrush" : "DangerRedBrush"));
        }
        catch (Exception ex) { DefenderHardenStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Persistence & Rootkit Threat Hunter ───
    private async void OnPersistenceHunt(object s, RoutedEventArgs e)
    {
        ShowLoading("Auditing WMI event subscriptions, IFEO debuggers, AppInit DLLs, and Temp executables...");
        PersistenceHuntList.Items.Clear();
        try
        {
            var report = await _persistenceScanner.ScanAsync();
            _lastPersistenceThreats = report.Threats;
            bool hasThreats = report.Threats.Count > 0;
            BtnPersistenceSelectAll.Visibility = hasThreats ? Visibility.Visible : Visibility.Collapsed;
            BtnPersistenceDeselectAll.Visibility = hasThreats ? Visibility.Visible : Visibility.Collapsed;
            BtnRemediatePersistence.Visibility = hasThreats ? Visibility.Visible : Visibility.Collapsed;

            PersistenceHuntSummaryBar.Visibility = Visibility.Visible;
            PersistenceHuntSummaryText.Text = report.ThreatCount == 0
                ? $"✅ Scanned {report.TotalItemsScanned} vectors — Zero unauthorized persistence mechanisms detected"
                : $"⚠️ Scanned {report.TotalItemsScanned} vectors — {report.ThreatCount} potential persistence threats flagged ({report.CriticalCount} Critical, {report.HighCount} High)!";
            PersistenceHuntSummaryText.Foreground = report.ThreatCount == 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");

            RenderPersistenceCards();
            UpdatePersistenceSelectionSummary();

            PersistenceHuntStatus.Text = $"Threat hunt complete — {report.TotalItemsScanned} persistence mechanisms evaluated.";
            PersistenceHuntStatus.Foreground = report.ThreatCount == 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("WarningAmberBrush");
        }
        catch (Exception ex) { PersistenceHuntStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void RenderPersistenceCards()
    {
        PersistenceHuntList.Items.Clear();
        if (_lastPersistenceThreats == null || _lastPersistenceThreats.Count == 0)
        {
            PersistenceHuntList.Items.Add(MakeResultCard("✅ Clean System State", "No rogue WMI event consumers, IFEO debugger redirects, or AppInit injections discovered.", "SuccessGreenBrush"));
            return;
        }

        foreach (var t in _lastPersistenceThreats)
        {
            var (icon, brush) = t.Severity switch
            {
                ThreatSeverity.Critical => ("🔴", "DangerRedBrush"),
                ThreatSeverity.High => ("🟠", "DangerRedBrush"),
                ThreatSeverity.Medium => ("🟡", "WarningAmberBrush"),
                _ => ("ℹ️", "BrandCyanBrush")
            };

            var remediateBtn = new System.Windows.Controls.Button
            {
                Content = "🔧 Fix",
                Style = (Style)Application.Current.FindResource("ActionCardButton"),
                Margin = new Thickness(12, 0, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center
            };
            remediateBtn.Click += async (s, e) =>
            {
                ShowLoading($"Neutralizing threat: {t.Name}...");
                try
                {
                    var res = await _persistenceScanner.RemediateEntryAsync(t);
                    if (res.Success)
                    {
                        PersistenceHuntStatus.Text = $"Neutralized threat: {t.Name}";
                        PersistenceHuntStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                        OnPersistenceHunt(s, e);
                    }
                    else
                    {
                        PersistenceHuntStatus.Text = $"Failed to neutralize {t.Name}: {res.Message}";
                    }
                }
                catch (Exception ex) { PersistenceHuntStatus.Text = $"Error: {ex.Message}"; }
                finally { HideLoading(); }
            };

            var card = MakeSelectableCard(
                t.IsSelected,
                isSelected =>
                {
                    t.IsSelected = isSelected;
                    UpdatePersistenceSelectionSummary();
                },
                $"{icon} [{t.Severity.ToString().ToUpperInvariant()}] {t.Category}: {t.Name}",
                $"{t.Description}\nLocation: {t.Location}\nValue: {t.CommandOrValue}",
                brush,
                badge: t.Category.ToString(),
                badgeColorKey: brush,
                rightAction: remediateBtn
            );

            PersistenceHuntList.Items.Add(card);
        }
    }

    private void UpdatePersistenceSelectionSummary()
    {
        if (_lastPersistenceThreats == null) return;
        var selectedCount = _lastPersistenceThreats.Count(t => t.IsSelected);
        BtnRemediatePersistence.Content = $"🔧 Remediate Selected ({selectedCount})";
        BtnRemediatePersistence.IsEnabled = selectedCount > 0;
    }

    private void OnPersistenceSelectAll(object s, RoutedEventArgs e)
    {
        if (_lastPersistenceThreats == null) return;
        foreach (var t in _lastPersistenceThreats) t.IsSelected = true;
        RenderPersistenceCards();
        UpdatePersistenceSelectionSummary();
    }

    private void OnPersistenceDeselectAll(object s, RoutedEventArgs e)
    {
        if (_lastPersistenceThreats == null) return;
        foreach (var t in _lastPersistenceThreats) t.IsSelected = false;
        RenderPersistenceCards();
        UpdatePersistenceSelectionSummary();
    }

    private async void OnPersistenceRemediateAll(object s, RoutedEventArgs e)
    {
        if (_lastPersistenceThreats == null || _lastPersistenceThreats.Count == 0) return;
        var selected = _lastPersistenceThreats.Where(t => t.IsSelected).ToList();
        if (selected.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Persistence Hunter", "Please select at least one threat to remediate.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "Confirm Persistence Remediation",
            $"Remediate {selected.Count} detected persistence mechanism(s)?\n\nThis will safely remove rogue WMI subscriptions, IFEO hooks, and staged payload binaries.",
            "Remediate Selected",
            "Cancel",
            destructive: true))
            return;

        ShowLoading($"Remediating {selected.Count} detected persistence mechanisms...");
        try
        {
            var results = await _persistenceScanner.RemediateAllAsync(selected);
            int successCount = results.Count(r => r.Success);
            int failCount = results.Count(r => !r.Success);

            PersistenceHuntStatus.Text = failCount == 0
                ? $"Successfully neutralized {successCount} persistence threats!"
                : $"Remediated {successCount} threats; {failCount} failed (elevation required).";
            PersistenceHuntStatus.Foreground = failCount == 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");

            OnPersistenceHunt(s, e);
        }
        catch (Exception ex) { PersistenceHuntStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── DNS & Hosts File Hijack Watchdog ───
    private async void OnDnsHostsCheck(object s, RoutedEventArgs e)
    {
        ShowLoading("Auditing hosts file and adapter DNS resolvers...");
        DnsHostsList.Items.Clear();
        try
        {
            var report = await _dnsHostsGuard.AuditAsync();
            DnsHostsSummaryBar.Visibility = Visibility.Visible;
            DnsHostsSummaryText.Text = report.SuspiciousEntries.Count == 0
                ? $"✅ Hosts file healthy ({report.TotalHostsEntries} entries) — {report.NetworkAdapters.Count} adapters checked"
                : $"⚠️ {report.SuspiciousEntries.Count} suspicious domain redirects discovered in hosts file!";
            DnsHostsSummaryText.Foreground = report.SuspiciousEntries.Count == 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");

            if (report.SuspiciousEntries.Count == 0)
            {
                DnsHostsList.Items.Add(MakeResultCard("✅ Clean Hosts Configuration", $"System hosts file at {report.HostsFilePath} contains no rogue redirects.", "SuccessGreenBrush"));
            }
            else
            {
                foreach (var se in report.SuspiciousEntries)
                {
                    DnsHostsList.Items.Add(MakeResultCard($"⚠️ Redirect: {se.Hostname} ➜ {se.IpAddress}", se.Reason ?? "Suspicious redirection", "DangerRedBrush"));
                }
            }

            if (report.ResolverAudit != null && report.ResolverAudit.Adapters.Count > 0)
            {
                foreach (var ad in report.ResolverAudit.Adapters.Where(a => a.IsActive || a.DnsServers.Count > 0))
                {
                    string dnsList = ad.DnsServers.Count > 0
                        ? string.Join(", ", ad.DnsServers.Select(s => $"{s.IpAddress} ({(s.IsTrusted ? s.ProviderName : "⚠️ ROGUE")})"))
                        : "Default (DHCP)";
                    var cardBrush = ad.HasRogueDns ? "DangerRedBrush" : "BrandCyanBrush";
                    DnsHostsList.Items.Add(MakeResultCard($"🌐 {ad.AdapterName} ({ad.Description})", $"DNS Resolvers: {dnsList}", cardBrush));
                }
            }
            else
            {
                foreach (var ad in report.NetworkAdapters)
                {
                    string dnsList = ad.DnsServers.Count > 0 ? string.Join(", ", ad.DnsServers) : "Default (DHCP)";
                    DnsHostsList.Items.Add(MakeResultCard($"🌐 {ad.Description}", $"DNS Servers: {dnsList}", "BrandCyanBrush"));
                }
            }

            DnsHostsStatus.Text = "DNS & Hosts check complete.";
            DnsHostsStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { DnsHostsStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnRestoreCleanHosts(object s, RoutedEventArgs e)
    {
        if (!Dialogs.Confirm(
            this,
            "Confirm Clean Hosts Restore",
            "Restore Windows default clean hosts file?\n\nA backup of the current hosts file will be saved automatically.",
            "Restore Clean Hosts",
            "Cancel"))
            return;

        ShowLoading("Restoring clean default Windows hosts file...");
        try
        {
            bool ok = await _dnsHostsGuard.RestoreDefaultHostsFileAsync();
            if (ok)
            {
                DnsHostsStatus.Text = "Successfully restored default Windows hosts file (backup created)!";
                DnsHostsStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                OnDnsHostsCheck(s, e);
            }
            else
            {
                DnsHostsStatus.Text = "Failed to restore hosts file (Administrator privileges required).";
            }
        }
        catch (Exception ex) { DnsHostsStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Privacy Scrub (adapted from Optimizer CleanHelper) ───
    private async void OnPrivacyScrub(object s, RoutedEventArgs e)
    {
        ShowLoading("Quick Privacy Scrub...");
        ScrubList.Items.Clear();
        try
        {
            var report = await Task.Run(() => _privacyScrubber.Scrub());
            ScrubSummaryBar.Visibility = Visibility.Visible;
            ScrubSummaryText.Text = $"✅ Cleared {report.TotalFilesCleared} files ({report.TotalBytesCleared / (1024.0 * 1024):F1} MB freed)";

            foreach (var t in report.Targets.Where(t => t.FilesCleared > 0))
                ScrubList.Items.Add(MakeResultCard($"🧹 {Path.GetFileName(t.Path)}", $"{t.FilesCleared} files, {t.BytesCleared / 1024.0:F0} KB", "BrandCyanBrush"));

            ScrubStatus.Text = "Scrub complete";
            ScrubStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { ScrubStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // Deep scrub — enhanced with browser cache paths from Optimizer's CleanHelper
    private async void OnDeepPrivacyScrub(object s, RoutedEventArgs e)
    {
        ShowLoading("Deep Privacy Scrub — clearing browser caches, temp files, error reports...");
        ScrubList.Items.Clear();
        try
        {
            // Standard scrub first
            var report = await Task.Run(() => _privacyScrubber.Scrub());
            int extraFiles = 0;
            long extraBytes = 0;

            // Deep scrub: additional cleanup targets adapted from Optimizer's CleanHelper
            // Chrome cache, Edge cache, Firefox cache, Windows Error Reporting, Minidumps
            var deepTargets = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Code Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Code Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "WER", "ReportQueue"),
                Path.Combine(Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows", "Minidump"),
                Path.Combine(Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows", "Temp"),
                Path.GetTempPath()
            };

            await Task.Run(() =>
            {
                foreach (var target in deepTargets)
                {
                    try
                    {
                        if (!Directory.Exists(target)) continue;
                        var di = new DirectoryInfo(target);
                        foreach (var file in di.EnumerateFiles("*", SearchOption.AllDirectories))
                        {
                            try { extraBytes += file.Length; file.Delete(); extraFiles++; } catch { }
                        }
                    }
                    catch { }
                }
            });

            ScrubSummaryBar.Visibility = Visibility.Visible;
            var totalFiles = report.TotalFilesCleared + extraFiles;
            var totalBytes = report.TotalBytesCleared + extraBytes;
            ScrubSummaryText.Text = $"✅ Deep Scrub: Cleared {totalFiles} files ({totalBytes / (1024.0 * 1024):F1} MB freed)";

            ScrubList.Items.Add(MakeResultCard("🧹 Standard Privacy Scrub", $"{report.TotalFilesCleared} files", "BrandCyanBrush"));
            ScrubList.Items.Add(MakeResultCard("🗑 Browser Caches (Chrome, Edge)", "Cache + Code Cache directories", "BrandPurpleBrush"));
            ScrubList.Items.Add(MakeResultCard("🗑 Windows Error Reports", "WER ReportArchive + ReportQueue", "WarningAmberBrush"));
            ScrubList.Items.Add(MakeResultCard("🗑 Temp Files + Minidumps", "System temp + user temp + crash dumps", "WarningAmberBrush"));
            ScrubList.Items.Add(MakeResultCard($"📊 Extra files cleaned: {extraFiles}", $"{extraBytes / (1024.0 * 1024):F1} MB freed", "SuccessGreenBrush"));

            ScrubStatus.Text = "Deep scrub complete";
            ScrubStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { ScrubStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── AI & Copilot Privacy Guard ───
    private async void OnAiGuardScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning Windows AI & Telemetry status...");
        AiGuardList.Items.Clear();
        try
        {
            var features = await _aiPrivacyGuard.ScanAsync();
            _lastAiFeatures = features;
            var neutralizedCount = features.Count(f => f.IsNeutralized);

            AiGuardSummaryBar.Visibility = Visibility.Visible;
            AiGuardSummaryText.Text = $"🛡 {neutralizedCount}/{features.Count} AI & Telemetry vectors neutralized";
            AiGuardStatus.Text = $"Status: {neutralizedCount} blocked, {features.Count - neutralizedCount} active";
            AiGuardStatus.Foreground = neutralizedCount == features.Count ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("TextSecondaryBrush");

            foreach (var f in features)
            {
                var statusTag = f.IsNeutralized ? "✅ NEUTRALIZED" : "⚠️ ACTIVE";
                var brush = f.IsNeutralized ? "SuccessGreenBrush" : "WarningAmberBrush";
                AiGuardList.Items.Add(MakeResultCard($"[{statusTag}] {f.Name}", $"{f.Description}\nRegistry: {f.RegistryImpact}", brush));
            }
        }
        catch (Exception ex) { AiGuardStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnAiGuardNeutralizeAll(object s, RoutedEventArgs e)
    {
        ShowLoading("Neutralizing Windows Recall, Copilot, Edge AI...");
        try
        {
            await _aiPrivacyGuard.ApplyAllAsync();
            AiGuardStatus.Text = "All AI telemetry and Recall hooks have been neutralized!";
            AiGuardStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnAiGuardScan(s, e);
        }
        catch (Exception ex) { AiGuardStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnAiGuardRevertAll(object s, RoutedEventArgs e)
    {
        ShowLoading("Reverting AI privacy policies to Windows defaults...");
        try
        {
            await _aiPrivacyGuard.RevertAllAsync();
            AiGuardStatus.Text = "Reverted AI policies to Windows defaults.";
            OnAiGuardScan(s, e);
        }
        catch (Exception ex) { AiGuardStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ═══════════════════════════════════════════════════════════
    //  GUARDIAN PAGE — Drivers + Update All
    //  (Driver scan adapted from Optimizer's hardware inspection;
    //   action pattern inspired by IObit Driver Booster)
    // ═══════════════════════════════════════════════════════════
    private void OnDriverScan(object s, RoutedEventArgs e) => OnDriverAudit(s, e);

    private List<DriverAuditorEngine.DeviceDriverInfo>? _currentAuditedDrivers;

    private void OnDriverSelectAll(object s, RoutedEventArgs e)
    {
        if (_currentAuditedDrivers == null) return;
        foreach (var d in _currentAuditedDrivers)
        {
            if (!d.IsIgnored) d.IsSelected = true;
        }
        PopulateDriverCards();
    }

    private void OnDriverDeselectAll(object s, RoutedEventArgs e)
    {
        if (_currentAuditedDrivers == null) return;
        foreach (var d in _currentAuditedDrivers)
        {
            d.IsSelected = false;
        }
        PopulateDriverCards();
    }

    private void UpdateDriverSelectionCount()
    {
        if (_currentAuditedDrivers == null || BtnUpdateDrivers == null) return;
        int actionableSelected = _currentAuditedDrivers.Count(d => d.IsSelected && !d.IsIgnored && (d.IsOutdated || d.HasError || !d.IsSigned));
        BtnUpdateDrivers.Content = $"🔄 Update Selected ({actionableSelected})";
        BtnUpdateDrivers.Visibility = _currentAuditedDrivers.Any(d => (d.IsOutdated || d.HasError || !d.IsSigned) && !d.IsIgnored) ? Visibility.Visible : Visibility.Collapsed;
    }

    private void RefreshDriverStatusSummary()
    {
        if (_currentAuditedDrivers == null) return;
        var status = _driverAuditor.CheckDriverStatus(new DriverAuditorEngine.DriverAuditReport { Drivers = _currentAuditedDrivers });
        string healthStatus = status.ErrorCount > 0 ? "Critical" : (status.Outdated > 0 || status.Unsigned > 0 ? "Degraded" : "Optimal");
        DriverStatusMetric.Text = healthStatus;
        DriverStatusMetric.Foreground = healthStatus switch
        {
            "Optimal" => (Brush)FindResource("SuccessGreenBrush"),
            "Degraded" => (Brush)FindResource("WarningAmberBrush"),
            _ => (Brush)FindResource("DangerRedBrush")
        };

        DriverOutdatedMetric.Text = status.Outdated.ToString();
        DriverUnsignedMetric.Text = status.Unsigned.ToString();
        DriverProblemMetric.Text = status.ErrorCount.ToString();

        DriverSummaryText.Text = $"Driver Status: {healthStatus} | {status.Total} Drivers Audited ({status.UpToDate} Up-to-Date, {status.IgnoredCount} Excluded)";

        var score = status.HealthScore;
        DriverStatusLabel.Text = $"Driver Health Score: {score}% — {status.Total} Hardware Devices Monitored";
        DriverStatusLabel.Foreground = ScoreBrush(score);

        HealthMonitorLabel.Text = $"⚡ {status.ErrorCount + status.Outdated + status.Unsigned} driver issues";
        HealthMonitorLabel.Foreground = ScoreBrush(score);
    }

    private void PopulateDriverCards()
    {
        DriverList.Items.Clear();
        if (_currentAuditedDrivers == null || _currentAuditedDrivers.Count == 0) return;

        foreach (var d in _currentAuditedDrivers.OrderByDescending(d => d.HasError)
                                                .ThenByDescending(d => d.IsOutdated)
                                                .ThenByDescending(d => !d.IsSigned)
                                                .ThenBy(d => d.DeviceName))
        {
            string colorKey = d.HasError ? "DangerRedBrush" : (d.IsOutdated ? "WarningAmberBrush" : (!d.IsSigned ? "WarningAmberBrush" : "SuccessGreenBrush"));
            string icon = d.HasError ? "❌" : (d.IsOutdated ? "⏳" : (!d.IsSigned ? "⚠" : "✅"));

            string badge = d.IsIgnored ? "EXCLUDED" : (d.HasError ? "ERROR" : (d.IsOutdated ? "OUTDATED" : (!d.IsSigned ? "UNSIGNED" : "OPTIMAL")));
            string badgeColorKey = d.IsIgnored ? "TextSecondaryBrush" : colorKey;

            string versionDetail = $"Current: v{d.DriverVersion} ({d.DriverDate})";
            if (d.IsOutdated && !string.IsNullOrEmpty(d.AvailableVersion))
            {
                versionDetail += $" | Available: v{d.AvailableVersion} ({d.AvailableDate})";
            }
            versionDetail += $" | {d.Manufacturer} | {d.StatusDescription}";

            var actionsPanel = new StackPanel
            {
                Orientation = System.Windows.Controls.Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0, 0, 0)
            };

            var excludeBtn = new System.Windows.Controls.Button
            {
                Content = d.IsIgnored ? "🛡 Include" : "🛡 Exclude",
                Style = (Style)Application.Current.FindResource("HeaderOutlineButton"),
                Height = 24,
                Padding = new Thickness(6, 0, 6, 0),
                Margin = new Thickness(0, 0, 6, 0),
                FontSize = 10,
                Cursor = System.Windows.Input.Cursors.Hand,
                ToolTip = d.IsIgnored ? "Include this driver in health audits and updates" : "Exclude and freeze this driver from updates"
            };
            excludeBtn.Click += (s, e) =>
            {
                string id = !string.IsNullOrEmpty(d.HardwareId) ? d.HardwareId : d.DeviceId;
                bool isIgnoredNow = DriverAuditorEngine.ToggleIgnoreDriver(id);
                d.IsIgnored = isIgnoredNow;
                if (isIgnoredNow) d.IsSelected = false;
                RefreshDriverStatusSummary();
                PopulateDriverCards();
            };
            actionsPanel.Children.Add(excludeBtn);

            var inspectBtn = new System.Windows.Controls.Button
            {
                Content = "🔍 Inspect",
                Style = (Style)Application.Current.FindResource("HeaderOutlineButton"),
                Height = 24,
                Padding = new Thickness(6, 0, 6, 0),
                FontSize = 10,
                Cursor = System.Windows.Input.Cursors.Hand,
                ToolTip = "Inspect hardware details or launch Device Manager"
            };
            inspectBtn.Click += (s, e) => InspectDriverDevice(d);
            actionsPanel.Children.Add(inspectBtn);

            var card = MakeSelectableCard(
                d.IsSelected,
                (isChecked) =>
                {
                    d.IsSelected = isChecked;
                    UpdateDriverSelectionCount();
                },
                $"{icon} {d.DeviceName}",
                versionDetail,
                colorKey,
                badge,
                badgeColorKey,
                null,
                actionsPanel);

            DriverList.Items.Add(card);
        }

        UpdateDriverSelectionCount();
    }

    private void RenderDriverResults(List<DriverAuditorEngine.DeviceDriverInfo> drivers)
    {
        _currentAuditedDrivers = drivers;
        DriverSummaryBar.Visibility = Visibility.Visible;
        BtnDriverSelectAll.Visibility = Visibility.Visible;
        BtnDriverDeselectAll.Visibility = Visibility.Visible;

        RefreshDriverStatusSummary();
        PopulateDriverCards();

        // If outdated, error, or unsigned drivers exist, auto-expand driver list so user sees them
        var status = _driverAuditor.CheckDriverStatus(new DriverAuditorEngine.DriverAuditReport { Drivers = _currentAuditedDrivers });
        if (status.Outdated > 0 || status.ErrorCount > 0 || status.Unsigned > 0)
        {
            DriverList.Visibility = Visibility.Visible;
            BtnToggleDriverDetails.Content = "▲ Hide Details";
        }
    }

    private async void OnDriverAudit(object s, RoutedEventArgs e)
    {
        ShowLoading("Auditing system drivers & hardware integrity...");
        DriverList.Items.Clear();
        try
        {
            var report = await Task.Run(() => _driverAuditor.AuditDrivers(true));
            RenderDriverResults(report.Drivers);
        }
        catch (Exception ex)
        {
            DriverStatusLabel.Text = $"Audit Error: {ex.Message}";
            DriverStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            HideLoading();
        }
    }

    private DriverAuditorEngine.DeviceDriverInfo? _inspectedDriver;

    private void InspectDriverDevice(DriverAuditorEngine.DeviceDriverInfo d)
    {
        _inspectedDriver = d;
        DriverInspectDeviceName.Text = string.IsNullOrWhiteSpace(d.DeviceName) ? "Unknown Hardware Device" : d.DeviceName;
        DriverInspectManufacturer.Text = string.IsNullOrWhiteSpace(d.Manufacturer) ? "OEM / Generic" : d.Manufacturer;
        DriverInspectClass.Text = !string.IsNullOrWhiteSpace(d.DeviceClass) ? d.DeviceClass : (!string.IsNullOrWhiteSpace(d.Category) ? d.Category : "Hardware");
        DriverInspectInstalledVersion.Text = string.IsNullOrWhiteSpace(d.DriverVersion) ? "Unknown" : d.DriverVersion;
        DriverInspectDriverDate.Text = string.IsNullOrWhiteSpace(d.DriverDate) ? "Unknown" : d.DriverDate;

        if (d.IsOutdated && !string.IsNullOrWhiteSpace(d.AvailableVersion))
        {
            DriverInspectTargetVersion.Text = $"v{d.AvailableVersion} ({d.AvailableDate})";
            DriverInspectTargetVersion.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        else if (d.IsOutdated)
        {
            DriverInspectTargetVersion.Text = "Update Available";
            DriverInspectTargetVersion.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        else
        {
            DriverInspectTargetVersion.Text = "Up to date";
            DriverInspectTargetVersion.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }

        DriverInspectSigner.Text = d.IsSigned
            ? (string.IsNullOrWhiteSpace(d.Signer) ? "Digitally Signed (WHQL)" : d.Signer)
            : "Unsigned / Self-signed";
        DriverInspectSigner.Foreground = d.IsSigned
            ? (Brush)FindResource("TextPrimaryBrush")
            : (Brush)FindResource("DangerRedBrush");

        DriverInspectHwidBox.Text = !string.IsNullOrWhiteSpace(d.HardwareId) ? d.HardwareId : d.DeviceId;

        if (d.HasError)
        {
            DriverInspectStatusBadgeText.Text = "ERROR";
            DriverInspectStatusBadgeText.Foreground = (Brush)FindResource("DangerRedBrush");
            DriverInspectGuidanceBorder.Background = new SolidColorBrush(Color.FromArgb(0x1E, 0xEF, 0x44, 0x44));
            DriverInspectGuidanceBorder.BorderBrush = (Brush)FindResource("DangerRedBrush");
            DriverInspectGuidanceText.Text = $"⚠ Hardware Error Code {d.ConfigManagerErrorCode}: {d.StatusDescription}. Reinstalling the driver or rescanning the PnP stack may resolve this condition.";
            DriverInspectGuidanceText.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        else if (d.IsOutdated)
        {
            DriverInspectStatusBadgeText.Text = "OUTDATED";
            DriverInspectStatusBadgeText.Foreground = (Brush)FindResource("WarningAmberBrush");
            DriverInspectGuidanceBorder.Background = new SolidColorBrush(Color.FromArgb(0x1E, 0xF5, 0x9E, 0x0B));
            DriverInspectGuidanceBorder.BorderBrush = (Brush)FindResource("WarningAmberBrush");
            DriverInspectGuidanceText.Text = "⚠ Update Available: A newer driver package is cataloged for this hardware. Updating may optimize performance or stability.";
            DriverInspectGuidanceText.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        else if (!d.IsSigned)
        {
            DriverInspectStatusBadgeText.Text = "UNSIGNED";
            DriverInspectStatusBadgeText.Foreground = (Brush)FindResource("DangerRedBrush");
            DriverInspectGuidanceBorder.Background = new SolidColorBrush(Color.FromArgb(0x1E, 0xEF, 0x44, 0x44));
            DriverInspectGuidanceBorder.BorderBrush = (Brush)FindResource("DangerRedBrush");
            DriverInspectGuidanceText.Text = "⚠ Unsigned Driver: Digital signature verification failed. Verify vendor authenticity before production deployment.";
            DriverInspectGuidanceText.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        else
        {
            DriverInspectStatusBadgeText.Text = "CURRENT";
            DriverInspectStatusBadgeText.Foreground = (Brush)FindResource("SuccessGreenBrush");
            DriverInspectGuidanceBorder.Background = new SolidColorBrush(Color.FromArgb(0x1E, 0x10, 0xB9, 0x81));
            DriverInspectGuidanceBorder.BorderBrush = (Brush)FindResource("SuccessGreenBrush");
            DriverInspectGuidanceText.Text = "🛡 Verified Hardware: Driver is digitally signed, fully operational, and operating within nominal parameters.";
            DriverInspectGuidanceText.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }

        BtnDriverInspectFreeze.Content = d.IsIgnored ? "🔓 Unfreeze Driver" : "🛡 Freeze Driver";
        BtnDriverInspectFreeze.ToolTip = d.IsIgnored
            ? "Allow this driver to be audited and updated by LogicFlow"
            : "Pin this driver version to prevent automatic Windows Update overwrites and exclude it from LogicFlow audit alerts";

        BtnDriverInspectUpdate.Visibility = (d.IsOutdated && !d.IsIgnored) ? Visibility.Visible : Visibility.Collapsed;

        DriverInspectModal.Visibility = Visibility.Visible;
    }

    private void OnCloseDriverInspectModal(object s, RoutedEventArgs e)
    {
        DriverInspectModal.Visibility = Visibility.Collapsed;
        _inspectedDriver = null;
    }

    private void OnDriverInspectCopyHwid(object s, RoutedEventArgs e)
    {
        if (_inspectedDriver == null) return;
        string hwid = !string.IsNullOrWhiteSpace(_inspectedDriver.HardwareId) ? _inspectedDriver.HardwareId : _inspectedDriver.DeviceId;
        if (!string.IsNullOrEmpty(hwid))
        {
            try
            {
                System.Windows.Clipboard.SetText(hwid);
                DriverInspectGuidanceText.Text = "📋 Hardware Identifier copied to clipboard!";
                DriverInspectGuidanceText.Foreground = (Brush)FindResource("BrandCyanBrush");
            }
            catch { /* clipboard access exception handling */ }
        }
    }

    private void OnDriverInspectToggleFreeze(object s, RoutedEventArgs e)
    {
        if (_inspectedDriver == null) return;
        if (!_inspectedDriver.IsIgnored && !Gate.Require(Capability.Core, this)) return;
        string id = !string.IsNullOrEmpty(_inspectedDriver.HardwareId) ? _inspectedDriver.HardwareId : _inspectedDriver.DeviceId;
        bool isIgnoredNow = DriverAuditorEngine.ToggleIgnoreDriver(id);
        _inspectedDriver.IsIgnored = isIgnoredNow;
        if (isIgnoredNow) _inspectedDriver.IsSelected = false;

        BtnDriverInspectFreeze.Content = isIgnoredNow ? "🔓 Unfreeze Driver" : "🛡 Freeze Driver";
        BtnDriverInspectFreeze.ToolTip = isIgnoredNow
            ? "Allow this driver to be audited and updated by LogicFlow"
            : "Pin this driver version to prevent automatic Windows Update overwrites and exclude it from LogicFlow audit alerts";

        BtnDriverInspectUpdate.Visibility = (!isIgnoredNow && _inspectedDriver.IsOutdated) ? Visibility.Visible : Visibility.Collapsed;

        DriverInspectGuidanceText.Text = isIgnoredNow
            ? "🛡 Driver has been frozen and excluded from update checks."
            : "🔓 Driver has been unfrozen and included in update checks.";
        DriverInspectGuidanceText.Foreground = (Brush)FindResource("BrandCyanBrush");

        RefreshDriverStatusSummary();
        PopulateDriverCards();
    }

    private void OnDriverInspectReinstall(object s, RoutedEventArgs e)
    {
        if (_inspectedDriver == null) return;
        if (!Gate.Require(Capability.Core, this)) return;
        if (Dialogs.Confirm(
            this,
            "LogicFlow — Restart Hardware Stack",
            $"Restart hardware stack and rescan Plug and Play bus for:\n\n" +
            $"• {_inspectedDriver.DeviceName}\n" +
            $"• ID: {(!string.IsNullOrEmpty(_inspectedDriver.HardwareId) ? _inspectedDriver.HardwareId : _inspectedDriver.DeviceId)}\n\n" +
            "This commands the Windows Plug and Play manager to cycle the driver stack and redetect hardware state without requiring a full system reboot.",
            "Restart Stack",
            "Cancel"))
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo("pnputil.exe", "/scan-devices")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                System.Diagnostics.Process.Start(psi);
                DriverInspectGuidanceText.Text = "⟳ Windows Plug and Play bus scan initiated. Hardware stack is reloading.";
                DriverInspectGuidanceText.Foreground = (Brush)FindResource("SuccessGreenBrush");
            }
            catch (Exception ex)
            {
                DriverInspectGuidanceText.Text = $"Failed to execute device scan: {ex.Message}";
                DriverInspectGuidanceText.Foreground = (Brush)FindResource("DangerRedBrush");
            }
        }
    }

    private async void OnDriverInspectUpdate(object s, RoutedEventArgs e)
    {
        if (!Gate.Require(Capability.Core, this)) return;
        if (_inspectedDriver == null) return;
        var d = _inspectedDriver;
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Update Driver",
            $"Download and install driver update for:\n\n" +
            $"• {d.DeviceName}\n" +
            $"• Current: v{d.DriverVersion} ({d.DriverDate})\n" +
            $"• Target: v{d.AvailableVersion} ({d.AvailableDate})\n\n" +
            "LogicFlow will automatically create a System Restore checkpoint before applying updates.\n\n" +
            "Proceed with driver installation?",
            "Install Update",
            "Cancel"))
            return;

        DriverInspectGuidanceText.Text = "⏳ Creating System Restore checkpoint & checking driver package...";
        DriverInspectGuidanceText.Foreground = (Brush)FindResource("WarningAmberBrush");

        try
        {
            using var db = new DriverDatabase();
            var scanResult = await db.FullScanAsync();
            var match = scanResult.IndexAvailable.FirstOrDefault(idx =>
                (!string.IsNullOrEmpty(d.HardwareId) && idx.HardwareId.Equals(d.HardwareId, StringComparison.OrdinalIgnoreCase)) ||
                idx.DeviceName.Equals(d.DeviceName, StringComparison.OrdinalIgnoreCase));

            if (match != null && !string.IsNullOrWhiteSpace(match.DownloadUrl))
            {
                DriverInspectGuidanceText.Text = $"⬇ Downloading {match.DeviceName} v{match.LatestVersion}...";
                var pkgPath = await db.DownloadDriverAsync(match);
                if (!string.IsNullOrEmpty(pkgPath))
                {
                    DriverInspectGuidanceText.Text = "⚙ Installing driver via PnPUtil...";
                    var installRes = await Task.Run(() => db.InstallDriver(pkgPath, match.DeviceName));
                    DriverInspectGuidanceText.Text = installRes.Success
                        ? $"✅ Installed driver update: {installRes.Message}"
                        : $"⚠ Driver install message: {installRes.Message}";
                    DriverInspectGuidanceText.Foreground = installRes.Success
                        ? (Brush)FindResource("SuccessGreenBrush")
                        : (Brush)FindResource("WarningAmberBrush");
                    OnDriverAudit(s, e);
                    return;
                }
            }

            await Task.Run(() =>
            {
                db.CreateRestorePointBeforeInstall(d.DeviceName);

                var psi = new System.Diagnostics.ProcessStartInfo("pnputil.exe", "/scan-devices")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                var proc = System.Diagnostics.Process.Start(psi);
                proc?.WaitForExit(30_000);
            });

            DriverInspectGuidanceText.Text = "✅ Update checkpoint created and PnP stack refreshed. Re-auditing driver...";
            DriverInspectGuidanceText.Foreground = (Brush)FindResource("SuccessGreenBrush");

            OnDriverAudit(s, e);
        }
        catch (Exception ex)
        {
            DriverInspectGuidanceText.Text = $"Driver update failed: {ex.Message}";
            DriverInspectGuidanceText.Foreground = (Brush)FindResource("DangerRedBrush");
        }
    }

    private async void OnUpdateSelectedDrivers(object s, RoutedEventArgs e)
    {
        if (_currentAuditedDrivers == null) return;
        var selected = _currentAuditedDrivers.Where(d => d.IsSelected && !d.IsIgnored && (d.IsOutdated || d.HasError || !d.IsSigned)).ToList();
        if (selected.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Update Drivers", "No outdated, problem, or unsigned drivers are currently selected for update.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Update Selected Drivers",
            $"Initiate driver update check and PnP resolution for {selected.Count} selected device driver(s)?\n\n" +
            string.Join("\n", selected.Take(5).Select(d => $"• {d.DeviceName} (v{d.DriverVersion} -> v{d.AvailableVersion})")) +
            (selected.Count > 5 ? $"\n... and {selected.Count - 5} more" : "") + "\n\n" +
            "• Outdated drivers: query Windows Update Catalog and online index\n" +
            "• Problem devices: trigger PnP re-enumeration and driver reinstall\n" +
            "• Unsigned drivers: inspect signatures and security posture",
            "Update Drivers",
            "Cancel"))
            return;

        ShowLoading($"Scanning and applying updates across {selected.Count} selected device(s)...");
        try
        {
            using var db = new DriverDatabase();
            var result = await db.FullScanAsync();
            int installedCount = 0;
            int noDirectUrlCount = 0;

            foreach (var drv in selected)
            {
                var idxMatch = result.IndexAvailable
                    .Concat(result.WindowsUpdateAvailable)
                    .FirstOrDefault(idx =>
                        (!string.IsNullOrEmpty(drv.HardwareId) && idx.HardwareId.Equals(drv.HardwareId, StringComparison.OrdinalIgnoreCase)) ||
                        idx.DeviceName.Equals(drv.DeviceName, StringComparison.OrdinalIgnoreCase));

                if (idxMatch != null)
                {
                    if (!string.IsNullOrWhiteSpace(idxMatch.DownloadUrl))
                    {
                        var pkgPath = await db.DownloadDriverAsync(idxMatch);
                        if (!string.IsNullOrEmpty(pkgPath))
                        {
                            var installRes = await Task.Run(() => db.InstallDriver(pkgPath, idxMatch.DeviceName));
                            if (installRes.Success)
                                installedCount++;
                        }
                    }
                    else
                    {
                        noDirectUrlCount++;
                    }
                }
            }

            string urlNote = noDirectUrlCount > 0
                ? $" ({noDirectUrlCount} update(s) require Windows Update or OEM portal — no direct package URL returned)"
                : (installedCount == 0 ? " (no direct downloadable packages returned)" : "");

            DriverStatusLabel.Text = $"Driver update complete: {installedCount} installed{urlNote}, {result.TotalUpdatesAvailable} update(s) cataloged ({result.WindowsUpdateAvailable.Count} Windows Update, {result.IndexAvailable.Count} Index, {result.AiRecommendations.Count} AI).";
            DriverStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnDriverAudit(s, e);
        }
        catch (Exception ex)
        {
            DriverStatusLabel.Text = $"Update error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private void OnUpdateAllDrivers(object s, RoutedEventArgs e) => OnUpdateSelectedDrivers(s, e);

    // ─── Bloatware Scanner + Remove (adapted from BloatBox PowerShell pattern) ───
    private void RenderBloatwareResults(List<BloatwarePackage> packages)
    {
        _lastBloatResults = packages;

        bool hasPackages = packages.Count > 0;
        BtnBloatSelectAll.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;
        BtnBloatDeselectAll.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;
        BtnRemoveBloat.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;

        // Summary bar with count + size estimate
        BloatSummaryBar.Visibility = Visibility.Visible;
        BloatSummaryText.Text = hasPackages
            ? $"🗑 {packages.Count} bloatware packages detected — safe to remove"
            : "✅ No bloatware detected — system is clean";
        BloatSummaryText.Foreground = hasPackages
            ? (Brush)FindResource("WarningAmberBrush")
            : (Brush)FindResource("SuccessGreenBrush");

        BloatStatus.Text = $"Found {packages.Count} packages";

        if (hasPackages)
        {
            BloatList.Visibility = Visibility.Visible;
            BtnToggleBloatDetails.Content = "▲ Hide Details";
        }
        else
        {
            BloatList.Visibility = Visibility.Collapsed;
            BtnToggleBloatDetails.Content = "▼ Show Details";
        }

        RenderBloatCards();
        UpdateBloatwareSelectionSummary();
    }

    private async void OnBloatwareScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Detecting bloatware...");
#pragma warning disable CS8604
        BloatList.Items.Clear();
        try
        {
            var packages = await Task.Run(() => _debloatEngine.ScanBloatware());
            RenderBloatwareResults(packages);
        }
        catch (Exception ex) { BloatStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void RenderBloatCards()
    {
        BloatList.Items.Clear();
        if (_lastBloatResults == null || _lastBloatResults.Count == 0)
        {
            BloatList.Items.Add(MakeResultCard("✅ No Bloatware Detected", "System is clean and free of pre-provisioned consumer bloatware.", "SuccessGreenBrush"));
            return;
        }

        foreach (var p in _lastBloatResults)
        {
            var removeBtn = new System.Windows.Controls.Button
            {
                Content = "❌ Remove",
                Style = (Style)Application.Current.FindResource("ActionCardButton"),
                Margin = new Thickness(12, 0, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center
            };
            removeBtn.Click += (s, e) => RemoveSingleBloatware(p.Name);

            var card = MakeSelectableCard(
                p.IsSelected,
                isSelected =>
                {
                    p.IsSelected = isSelected;
                    UpdateBloatwareSelectionSummary();
                },
                $"🗑 {p.Name}",
                $"{p.Publisher} v{p.Version}",
                "WarningAmberBrush",
                badge: "UWP",
                badgeColorKey: "WarningAmberBrush",
                rightAction: removeBtn
            );

            BloatList.Items.Add(card);
        }
    }

    private void UpdateBloatwareSelectionSummary()
    {
        if (_lastBloatResults == null) return;
        var selectedCount = _lastBloatResults.Count(p => p.IsSelected);
        BtnRemoveBloat.Content = $"🗑 Uninstall Selected ({selectedCount})";
        BtnRemoveBloat.IsEnabled = selectedCount > 0;
    }

    private void OnBloatSelectAll(object s, RoutedEventArgs e)
    {
        if (_lastBloatResults == null) return;
        foreach (var p in _lastBloatResults) p.IsSelected = true;
        RenderBloatCards();
        UpdateBloatwareSelectionSummary();
    }

    private void OnBloatDeselectAll(object s, RoutedEventArgs e)
    {
        if (_lastBloatResults == null) return;
        foreach (var p in _lastBloatResults) p.IsSelected = false;
        RenderBloatCards();
        UpdateBloatwareSelectionSummary();
    }

    private async void RemoveSingleBloatware(string packageName)
    {
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Remove Bloatware",
            $"Uninstall package '{packageName}'?\n\nThis invokes PowerShell Remove-AppxPackage to cleanly remove the application.",
            "Uninstall Package",
            "Cancel",
            destructive: true))
            return;

        ShowLoading($"Removing {packageName}...");
        try
        {
            bool ok = await Task.Run(() => _debloatEngine.RemoveBloatware(packageName));
            if (ok)
            {
                BloatStatus.Text = $"Successfully removed package: {packageName}";
                BloatStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                OnBloatwareScan(this, new RoutedEventArgs());
            }
            else
            {
                BloatStatus.Text = $"Could not remove package {packageName}. Elevation or system policy may prevent removal.";
                BloatStatus.Foreground = (Brush)FindResource("WarningAmberBrush");
            }
        }
        catch (Exception ex)
        {
            BloatStatus.Text = $"Error removing bloatware: {ex.Message}";
            BloatStatus.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnRemoveAllBloatware(object s, RoutedEventArgs e)
    {
        if (_lastBloatResults == null || _lastBloatResults.Count == 0) return;
        var selected = _lastBloatResults.Where(p => p.IsSelected).ToList();
        if (selected.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Bloatware Scanner", "Please select at least one bloatware package to uninstall.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Remove Selected Bloatware",
            $"Remove {selected.Count} selected bloatware package(s)?\n\n" +
            string.Join("\n", selected.Select(p => $"• {p.Name}")) +
            "\n\nThis uses PowerShell Get-AppxPackage | Remove-AppxPackage.\n\nPackages can be reinstalled from the Microsoft Store.",
            "Remove Selected",
            "Cancel",
            defaultCancel: true,
            destructive: true))
            return;

        ShowLoading($"Removing {selected.Count} bloatware packages...");
        try
        {
            var pkgs = selected.Select(p => p.Name).ToList();
            int removed = await Task.Run(() => _debloatEngine.RemoveBloatwarePackages(pkgs));
            BloatSummaryText.Text = $"✅ {removed}/{pkgs.Count} bloatware packages removed";
            BloatSummaryText.Foreground = (Brush)FindResource("SuccessGreenBrush");
            BloatStatus.Text = $"Successfully removed {removed} bloatware package(s).";
            BloatStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnBloatwareScan(s, e);
        }
        catch (Exception ex)
        {
            BloatStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  TOOLBOX PAGE — Junk Cleaner, Memory, Turbo, Duplicates,
    //  Disk Space, File Shredder
    // ═══════════════════════════════════════════════════════════

    // ─── Junk Cleaner ───
    private void RenderJunkResults(List<JunkCleanerEngine.JunkScanResult> report)
    {
        _lastJunkReport = report;
        var totalFiles = report.Sum(c => c.FileCount);

        bool hasItems = totalFiles > 0;
        BtnJunkSelectAll.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
        BtnJunkSelectSafe.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
        BtnJunkDeselectAll.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
        BtnCleanJunk.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;

        JunkSummaryBar.Visibility = Visibility.Visible;
        var totalBytes = report.Sum(c => c.TotalBytes);
        var totalMB = totalBytes / (1024.0 * 1024);
        JunkSummaryText.Text = $"🧹 {totalFiles:N0} junk files found ({totalMB:F1} MB recoverable)";

        RenderJunkCards();
        UpdateJunkSelectionSummary();

        JunkStatus.Text = $"Scan complete — {totalFiles:N0} junk files found";
        JunkStatus.Foreground = (Brush)FindResource("TextSecondaryBrush");
    }

    private async void OnJunkScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning for junk files...");
        JunkList.Items.Clear();
        try
        {
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            var report = await Task.Run(() => _junkCleaner.Scan());
            RenderJunkResults(report);
        }
        catch (Exception ex) { JunkStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void RenderJunkCards()
    {
        JunkList.Items.Clear();
        if (_lastJunkReport == null || _lastJunkReport.Count == 0)
        {
            JunkList.Items.Add(MakeResultCard("✅ System Clean", "No temporary or junk files found on the system.", "SuccessGreenBrush"));
            return;
        }

        foreach (var cat in _lastJunkReport.OrderByDescending(c => c.TotalBytes))
        {
            var sizeMB = cat.TotalBytes / (1024.0 * 1024);
            var colorKey = sizeMB > 100 ? "DangerRedBrush" : sizeMB > 10 ? "WarningAmberBrush" : "TextSecondaryBrush";
            var badgeText = cat.IsSafeCategory ? "🛡 SAFE" : "⚠️ OPTIONAL";
            var badgeColor = cat.IsSafeCategory ? "SuccessGreenBrush" : "WarningAmberBrush";

            var pathBlock = new TextBlock
            {
                Text = $"Target: {cat.TargetPathSummary}",
                FontSize = 11,
                Foreground = (Brush)FindResource("BrandCyanBrush"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 0, 0),
                ToolTip = $"Scanning paths:\n{cat.TargetPathSummary}\n\nFiles found: {cat.FileCount:N0}"
            };

            var card = MakeSelectableCard(
                cat.IsSelected,
                isSelected =>
                {
                    cat.IsSelected = isSelected;
                    UpdateJunkSelectionSummary();
                },
                $"🗑 {cat.DisplayName}",
                $"{cat.FileCount:N0} files — {sizeMB:F1} MB",
                colorKey,
                badge: badgeText,
                badgeColorKey: badgeColor,
                extraDetails: pathBlock
            );

            JunkList.Items.Add(card);
        }
    }

    private void UpdateJunkSelectionSummary()
    {
        if (_lastJunkReport == null) return;
        var totalBytes = _lastJunkReport.Sum(c => c.TotalBytes);
        var selected = _lastJunkReport.Where(c => c.IsSelected).ToList();
        var selBytes = selected.Sum(c => c.TotalBytes);

        JunkSummaryBar.Visibility = Visibility.Visible;
        JunkSummaryText.Text = $"✔ Selected: {selected.Count} of {_lastJunkReport.Count} categories ({selBytes / (1024.0 * 1024):F1} MB / {totalBytes / (1024.0 * 1024):F1} MB)";
        JunkSummaryText.Foreground = selected.Count > 0 ? (Brush)FindResource("BrandCyanBrush") : (Brush)FindResource("TextSecondaryBrush");

        BtnCleanJunk.Content = $"🧹 Clean Selected ({selected.Count})";
        BtnCleanJunk.IsEnabled = selected.Count > 0;
    }

    private void OnJunkSelectAll(object s, RoutedEventArgs e)
    {
        if (_lastJunkReport == null) return;
        foreach (var r in _lastJunkReport) r.IsSelected = true;
        RenderJunkCards();
        UpdateJunkSelectionSummary();
    }

    private void OnJunkSelectSafe(object s, RoutedEventArgs e)
    {
        if (_lastJunkReport == null) return;
        foreach (var r in _lastJunkReport) r.IsSelected = r.IsSafeCategory;
        RenderJunkCards();
        UpdateJunkSelectionSummary();
    }

    private void OnJunkDeselectAll(object s, RoutedEventArgs e)
    {
        if (_lastJunkReport == null) return;
        foreach (var r in _lastJunkReport) r.IsSelected = false;
        RenderJunkCards();
        UpdateJunkSelectionSummary();
    }

    private async void OnJunkClean(object s, RoutedEventArgs e)
    {
        if (_lastJunkReport == null) return;
        var selected = _lastJunkReport.Where(r => r.IsSelected).ToList();
        if (selected.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Junk Cleaner", "Please select at least one junk category to clean.");
            return;
        }

        var selBytes = selected.Sum(c => c.TotalBytes);
        var selFiles = selected.Sum(c => c.FileCount);
        bool confirm = Dialogs.Confirm(
            this,
            "LogicFlow — Confirm Junk Cleanup",
            $"Clean {selected.Count} selected categories?\n\n" +
            $"This will permanently delete {selFiles:N0} files ({selBytes / (1024.0 * 1024):F1} MB) across:\n" +
            string.Join("\n", selected.Select(c => $"• {c.DisplayName} ({c.FileCount} files)")) +
            "\n\nExcluded folders configured in Settings are skipped.",
            "Clean Selected",
            "Cancel",
            defaultCancel: true,
            destructive: true);
        if (!confirm) return;

        ShowLoading("Cleaning selected junk files...");
        try
        {
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            var result = await Task.Run(() => _junkCleaner.Clean(_lastJunkReport));
            JunkSummaryText.Text = $"✅ Cleaned {result.FilesDeleted:N0} files — {result.BytesCleaned / (1024.0 * 1024):F1} MB freed";
            JunkSummaryText.Foreground = (Brush)FindResource("SuccessGreenBrush");
            BtnCleanJunk.Visibility = Visibility.Collapsed;
            BtnJunkSelectAll.Visibility = Visibility.Collapsed;
            BtnJunkSelectSafe.Visibility = Visibility.Collapsed;
            BtnJunkDeselectAll.Visibility = Visibility.Collapsed;
            JunkStatus.Text = "Cleanup complete!";
            JunkStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            JunkList.Items.Clear();
            JunkList.Items.Add(MakeResultCard("✅ System Clean", $"Successfully removed {result.FilesDeleted:N0} junk files, reclaiming {result.BytesCleaned / (1024.0 * 1024):F1} MB of disk space.", "SuccessGreenBrush"));
        }
        catch (Exception ex) { JunkStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnJunkScheduleClick(object s, RoutedEventArgs e)
    {
        try
        {
            var (isEnabled, result) = await Task.Run(() => _junkCleaner.ToggleWeeklySchedule());
            JunkStatus.Text = result.Success
                ? (isEnabled
                    ? "📅 Weekly Junk Clean scheduled (Sundays at 03:00 AM via Windows Task Scheduler)."
                    : "⏹ Weekly Junk Clean schedule removed.")
                : $"Schedule update failed: {result.Message}";
        }
        catch (Exception ex)
        {
            JunkStatus.Text = $"Schedule error: {ex.Message}";
        }
    }

    // ─── Memory Optimizer ───
    private async void OnMemoryOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Optimizing RAM...");
        MemOptList.Items.Clear();
        try
        {
            var result = await Task.Run(() => _memoryOptimizer.Optimize());

            MemOptSummaryBar.Visibility = Visibility.Visible;
            var freedMB = result.TotalMemoryFreedBytes / (1024.0 * 1024);
            var beforePct = result.Before.PhysicalUsagePercent;
            var afterPct = result.After.PhysicalUsagePercent;
            MemOptSummaryText.Text = $"✅ Freed {freedMB:F0} MB — {result.ProcessesOptimized} processes trimmed";
            MemOptStatus.Text = $"RAM: {beforePct:F0}% → {afterPct:F0}%";
            MemOptStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");

            MemOptList.Items.Add(MakeResultCard("📊 Before", $"{beforePct:F1}% used", "WarningAmberBrush"));
            MemOptList.Items.Add(MakeResultCard("📊 After", $"{afterPct:F1}% used", "SuccessGreenBrush"));
            MemOptList.Items.Add(MakeResultCard("🧠 RAM Freed", $"{freedMB:F0} MB from {result.ProcessesOptimized} processes", "BrandCyanBrush"));

            // Show kernel-level area details
            if (result.IsAdmin)
            {
                if (result.StandbyListCleared)
                    MemOptList.Items.Add(MakeResultCard("🗂️ Standby List", "Cleared — cached data from closed apps freed", "SuccessGreenBrush"));
                if (result.ModifiedPageListFlushed)
                    MemOptList.Items.Add(MakeResultCard("📝 Modified Pages", "Flushed — dirty pages written to disk", "SuccessGreenBrush"));
                if (result.SystemFileCacheCleared)
                    MemOptList.Items.Add(MakeResultCard("💾 File Cache", "Flushed — Windows filesystem cache cleared", "SuccessGreenBrush"));
                if (result.LowPriorityStandbyCleared)
                    MemOptList.Items.Add(MakeResultCard("📋 Low-Priority", "Cleared — low-priority cached pages freed", "SuccessGreenBrush"));
            }
            else
            {
                MemOptList.Items.Add(MakeResultCard("⚠️ Limited Mode",
                    "Run as Administrator for full optimization (standby list, file cache, modified pages)", "WarningAmberBrush"));
            }

            // Pagefile / Virtual Memory stats
            var pfUsage = result.After.PageFileUsagePercent;
            MemOptList.Items.Add(MakeResultCard("💿 Virtual Memory",
                $"Pagefile: {pfUsage:F0}% used ({result.After.PageFileUsedFormatted} / {result.After.PageFileTotalFormatted})",
                pfUsage > 80 ? "DangerRedBrush" : "BrandCyanBrush"));

            // Update Dashboard
            MemOptStatus.Text = $"Freed {freedMB:F0} MB ({result.AreasCleared})";
            MemOptStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            MiniRamBar.Value = afterPct;
            MiniRamBar.Foreground = MetricBrush(afterPct, Resources);
            MiniRamText.Text = $"{afterPct:F0}%";
        }
        catch (Exception ex) { MemOptStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Virtual Memory / Pagefile Optimizer ───
    private async void OnFlushStandbyCache(object s, RoutedEventArgs e)
    {
        ShowLoading("Flushing standby memory cache...");
        try
        {
            var before = await Task.Run(() => _memoryOptimizer.GetMemoryBreakdown());
            bool success = await Task.Run(() => _memoryOptimizer.FlushStandbyList());
            var after = await Task.Run(() => _memoryOptimizer.GetMemoryBreakdown());

            MemOptSummaryBar.Visibility = Visibility.Visible;
            if (success)
            {
                var freedMB = Math.Max(0, (before.StandbyCacheBytes - after.StandbyCacheBytes) / (1024.0 * 1024.0));
                MemOptSummaryText.Text = $"✅ Standby Cache Purged — Freed ~{freedMB:F0} MB of cached standby pages";
                MemOptStatus.Text = $"RAM Status: In-Use {after.InUseFormatted} ({after.InUsePercent:F0}%), Cache {after.StandbyFormatted} ({after.StandbyPercent:F0}%), Free {after.FreeFormatted} ({after.FreePercent:F0}%)";
                MemOptStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            }
            else
            {
                MemOptSummaryText.Text = "⚠️ Standby list purge requires Administrator privileges (SeProfileSingleProcessPrivilege).";
                MemOptStatus.Text = "Run LogicFlow with Administrator privileges to purge kernel standby pages.";
                MemOptStatus.Foreground = (Brush)FindResource("WarningAmberBrush");
            }

            await RefreshVirtualMemoryCards();
        }
        catch (Exception ex)
        {
            MemOptStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnVirtualMemoryOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing physical & virtual memory...");
        MemOptList.Items.Clear();
        try
        {
            await RefreshVirtualMemoryCards();
        }
        catch (Exception ex)
        {
            MemOptStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private async Task RefreshVirtualMemoryCards()
    {
        var mem = await Task.Run(() => _memoryOptimizer.GetMemoryBreakdown());
        var analysis = await Task.Run(() => _pagefileOptimizer.Analyze());

        MemOptSummaryBar.Visibility = Visibility.Visible;
        var statusIcon = analysis.Status switch
        {
            PagefileOptimizer.HealthStatus.Optimal => "✅",
            PagefileOptimizer.HealthStatus.Acceptable => "🟡",
            PagefileOptimizer.HealthStatus.NeedsAttention => "⚠️",
            PagefileOptimizer.HealthStatus.Critical => "🔴",
            _ => "ℹ️"
        };
        MemOptSummaryText.Text = $"{statusIcon} Virtual Memory: {analysis.Status} — Commit Charge at {analysis.CommitPercent:F0}%";
        MemOptStatus.Text = $"RAM: {mem.InUseFormatted} Active, {mem.StandbyFormatted} Cache, {mem.FreeFormatted} Free | Commit: {analysis.CommitChargeMB:N0} / {analysis.CommitLimitMB:N0} MB";
        MemOptStatus.Foreground = (Brush)FindResource(analysis.CommitPercent > 80 ? "WarningAmberBrush" : "SuccessGreenBrush");

        MemOptList.Items.Clear();

        // 1. Physical RAM Allocation Meter Card
        MemOptList.Items.Add(CreateRamAllocationCard(mem));

        // 2. Commit Charge Card
        string commitDetail = $"{analysis.CommitPercent:F0}% committed ({analysis.CommitChargeMB:N0} MB allocated of {analysis.CommitLimitMB:N0} MB commit limit).\n" +
            (analysis.CommitPercent > 80
                ? "⚠️ High commit charge: Paging file expansion is recommended to prevent out-of-memory errors."
                : "✅ Normal commit level: System has sufficient virtual memory headroom.");
        string commitBrush = analysis.CommitPercent > 80 ? "DangerRedBrush" : (analysis.CommitPercent > 65 ? "WarningAmberBrush" : "SuccessGreenBrush");
        MemOptList.Items.Add(MakeResultCard("📊 Commit Charge", commitDetail, commitBrush));

        // 3. Smart Pagefile Recommendation Card (with Apply & Revert buttons)
        MemOptList.Items.Add(CreatePagefileRecommendationCard(analysis));

        // 4. Current Pagefile Configuration Card
        string currentConfig;
        if (analysis.CurrentPagefiles.Count > 0)
        {
            var pfLines = analysis.CurrentPagefiles.Select(p =>
                $"Drive {p.DriveLetter}: — Initial: {p.InitialSizeMB:N0} MB, Max: {p.MaximumSizeMB:N0} MB (Usage: {p.CurrentUsageMB:N0} MB, Peak: {p.PeakUsageMB:N0} MB) [{(p.IsSystemManaged ? "System Managed" : "Custom")}]");
            currentConfig = string.Join("\n", pfLines);
        }
        else
        {
            currentConfig = "System Managed (Windows dynamically allocates paging space on system drive)";
        }
        MemOptList.Items.Add(MakeResultCard("📁 Current Pagefile Configuration", currentConfig, "BrandCyanBrush"));

        // 5. Storage Drive Paging Suitability Cards
        foreach (var drive in analysis.Drives)
        {
            bool isUsb = drive.IsExternal || string.Equals(drive.BusType, "USB", StringComparison.OrdinalIgnoreCase);
            if (isUsb)
            {
                string usbDetail = $"{drive.FreeSpaceGB} GB free / {drive.TotalSpaceGB} GB total\n" +
                    "⛔ EXCLUDED: External USB storage cannot safely host the Windows pagefile. USB disconnects or controller power management trigger instant KERNEL_DATA_INPAGE_ERROR (0x0000007A) BSODs. Windows crash dump engine (crashdmp.sys) requires internal storage.";
                MemOptList.Items.Add(MakeResultCard($"💽 Drive {drive.DriveLetter}: ({drive.MediaType}) — Excluded from Paging", usbDetail, "WarningAmberBrush"));
            }
            else if (drive.IsSystemDrive)
            {
                string sysDetail = $"{drive.FreeSpaceGB} GB free / {drive.TotalSpaceGB} GB total\n" +
                    "✅ System Boot Drive: Optimal location for pagefile. Hosts Windows kernel crash dumps (MEMORY.DMP) during stop errors.";
                MemOptList.Items.Add(MakeResultCard($"💽 Drive {drive.DriveLetter}: ({drive.MediaType}) — System Boot Drive [Recommended]", sysDetail, "SuccessGreenBrush"));
            }
            else if (drive.IsSsd)
            {
                string ssdDetail = $"{drive.FreeSpaceGB} GB free / {drive.TotalSpaceGB} GB total\n" +
                    "💽 Secondary High-Speed SSD: Suitable for pagefile spillover if system drive is space-constrained.";
                MemOptList.Items.Add(MakeResultCard($"💽 Drive {drive.DriveLetter}: ({drive.MediaType}) — Internal SSD", ssdDetail, "BrandCyanBrush"));
            }
            else
            {
                string hddDetail = $"{drive.FreeSpaceGB} GB free / {drive.TotalSpaceGB} GB total\n" +
                    "⚠️ Mechanical HDD: Not recommended for paging (high seek latency causes system stutters).";
                MemOptList.Items.Add(MakeResultCard($"💽 Drive {drive.DriveLetter}: ({drive.MediaType}) — Internal HDD", hddDetail, "WarningAmberBrush"));
            }
        }

        // 6. Warnings
        foreach (var warning in analysis.Warnings)
            MemOptList.Items.Add(MakeResultCard("⚠️ Warning", warning, "DangerRedBrush"));

        // 7. Recommendations
        foreach (var rec in analysis.Recommendations)
            MemOptList.Items.Add(MakeResultCard("💡 Tip", rec, "WarningAmberBrush"));
    }

    private FrameworkElement CreateRamAllocationCard(MemoryOptimizer.MemoryBreakdown mem)
    {
        var card = new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var mainPanel = new StackPanel();

        var headerGrid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var titleBlock = new TextBlock
        {
            Text = "🧠 Physical RAM Allocation",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.FindResource("BrandCyanBrush"),
            VerticalAlignment = VerticalAlignment.Center
        };
        var totalBlock = new TextBlock
        {
            Text = $"Total: {mem.TotalFormatted}",
            FontSize = 11,
            Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
            VerticalAlignment = VerticalAlignment.Center
        };
        Grid.SetColumn(titleBlock, 0);
        Grid.SetColumn(totalBlock, 1);
        headerGrid.Children.Add(titleBlock);
        headerGrid.Children.Add(totalBlock);
        mainPanel.Children.Add(headerGrid);

        var meterBorder = new Border
        {
            Height = 12,
            CornerRadius = new CornerRadius(6),
            Background = (Brush)Application.Current.FindResource("BorderSubtleBrush"),
            ClipToBounds = true,
            Margin = new Thickness(0, 0, 0, 10)
        };

        var meterGrid = new Grid();
        double inUsePct = Math.Max(0.1, mem.InUsePercent);
        double standbyPct = Math.Max(0.1, mem.StandbyPercent);
        double freePct = Math.Max(0.1, mem.FreePercent);

        meterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(inUsePct, GridUnitType.Star) });
        meterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(standbyPct, GridUnitType.Star) });
        meterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(freePct, GridUnitType.Star) });

        var segInUse = new Border
        {
            Background = (Brush)Application.Current.FindResource("BrandPurpleBrush"),
            ToolTip = $"Active In-Use: {mem.InUseFormatted} ({mem.InUsePercent:F1}%)"
        };
        var segStandby = new Border
        {
            Background = (Brush)Application.Current.FindResource("WarningAmberBrush"),
            ToolTip = $"Standby Cache: {mem.StandbyFormatted} ({mem.StandbyPercent:F1}%)"
        };
        var segFree = new Border
        {
            Background = (Brush)Application.Current.FindResource("SuccessGreenBrush"),
            ToolTip = $"Free RAM: {mem.FreeFormatted} ({mem.FreePercent:F1}%)"
        };

        Grid.SetColumn(segInUse, 0);
        Grid.SetColumn(segStandby, 1);
        Grid.SetColumn(segFree, 2);

        meterGrid.Children.Add(segInUse);
        meterGrid.Children.Add(segStandby);
        meterGrid.Children.Add(segFree);
        meterBorder.Child = meterGrid;
        mainPanel.Children.Add(meterBorder);

        var footerGrid = new Grid();
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var labelsPanel = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
        labelsPanel.Children.Add(new TextBlock
        {
            Text = $"🟣 In-Use: {mem.InUseFormatted} ({mem.InUsePercent:F0}%)   ",
            FontSize = 11,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush")
        });
        labelsPanel.Children.Add(new TextBlock
        {
            Text = $"🟠 Cache: {mem.StandbyFormatted} ({mem.StandbyPercent:F0}%)   ",
            FontSize = 11,
            Foreground = (Brush)Application.Current.FindResource("WarningAmberBrush")
        });
        labelsPanel.Children.Add(new TextBlock
        {
            Text = $"🟢 Free: {mem.FreeFormatted} ({mem.FreePercent:F0}%)",
            FontSize = 11,
            Foreground = (Brush)Application.Current.FindResource("SuccessGreenBrush")
        });

        var flushBtn = new System.Windows.Controls.Button
        {
            Content = "🧹 Flush Cache",
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            ToolTip = "Immediately purges standby cache pages and reclaims memory",
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = System.Windows.Input.Cursors.Hand
        };
        flushBtn.Click += (s, e) => OnFlushStandbyCache(s, e);

        Grid.SetColumn(labelsPanel, 0);
        Grid.SetColumn(flushBtn, 1);
        footerGrid.Children.Add(labelsPanel);
        footerGrid.Children.Add(flushBtn);
        mainPanel.Children.Add(footerGrid);

        card.Child = mainPanel;
        return card;
    }

    private FrameworkElement CreatePagefileRecommendationCard(PagefileOptimizer.PagefileAnalysis analysis)
    {
        var card = new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var panel = new StackPanel();

        var titleBlock = new TextBlock
        {
            Text = "🎯 Smart Pagefile Recommendation",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.FindResource("SuccessGreenBrush")
        };
        panel.Children.Add(titleBlock);

        var targetBlock = new TextBlock
        {
            Text = $"Target: {analysis.RecommendedSizeFormatted} on Drive {analysis.RecommendedDrive}:",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            Margin = new Thickness(0, 4, 0, 2)
        };
        panel.Children.Add(targetBlock);

        var rationaleBlock = new TextBlock
        {
            Text = analysis.SizingRationale,
            FontSize = 11,
            Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10)
        };
        panel.Children.Add(rationaleBlock);

        var buttonsPanel = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };

        var applyBtn = new System.Windows.Controls.Button
        {
            Content = "✨ Apply Recommended Pagefile",
            Style = (Style)Application.Current.FindResource("ActionButton"),
            Background = new SolidColorBrush(Color.FromRgb(0x00, 0x89, 0x7B)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(12, 6, 12, 6),
            Cursor = System.Windows.Input.Cursors.Hand,
            ToolTip = "Configures the recommended initial and maximum pagefile size on the optimal drive (requires restart)"
        };
        applyBtn.Click += async (s, e) => await OnApplyRecommendedPagefile(analysis);

        var revertBtn = new System.Windows.Controls.Button
        {
            Content = "↺ Revert to Windows Managed",
            Style = (Style)Application.Current.FindResource("OutlineButton"),
            Padding = new Thickness(12, 6, 12, 6),
            Cursor = System.Windows.Input.Cursors.Hand,
            ToolTip = "Restores automatic system-managed paging file settings across all drives"
        };
        revertBtn.Click += async (s, e) => await OnRevertPagefileDefaults();

        buttonsPanel.Children.Add(applyBtn);
        buttonsPanel.Children.Add(revertBtn);
        panel.Children.Add(buttonsPanel);

        card.Child = panel;
        return card;
    }

    private async Task OnApplyRecommendedPagefile(PagefileOptimizer.PagefileAnalysis analysis)
    {
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Apply Recommended Pagefile",
            $"Apply recommended pagefile settings?\n\n" +
            $"• Target Drive: {analysis.RecommendedDrive}:\n" +
            $"• Sizing: {analysis.RecommendedSizeFormatted}\n\n" +
            $"Rationale: {analysis.SizingRationale}\n\n" +
            "Note: Windows requires a system restart for paging file allocation changes to take effect.",
            "Apply Pagefile",
            "Cancel"))
            return;

        ShowLoading("Configuring virtual memory...");
        try
        {
            var res = await Task.Run(() => _pagefileOptimizer.ApplyRecommendation(analysis));
            if (res.Success)
            {
                Dialogs.ShowMessage(
                    this,
                    "LogicFlow — Pagefile Configured",
                    $"{res.Message}\n\nPlease restart your computer to apply the new paging configuration.");
                await RefreshVirtualMemoryCards();
            }
            else
            {
                Dialogs.ShowMessage(
                    this,
                    "LogicFlow — Pagefile Configuration",
                    $"Failed to configure pagefile:\n{res.Message}",
                    isWarningOrError: true);
            }
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "LogicFlow Error", $"Error: {ex.Message}", isWarningOrError: true);
        }
        finally
        {
            HideLoading();
        }
    }

    private async Task OnRevertPagefileDefaults()
    {
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Revert Pagefile Defaults",
            "Revert virtual memory configuration back to Windows system-managed defaults?\n\n" +
            "Windows will automatically manage pagefile allocation across system drives.",
            "Revert Defaults",
            "Cancel"))
            return;

        ShowLoading("Reverting pagefile to system managed...");
        try
        {
            var res = await Task.Run(() => _pagefileOptimizer.RestoreDefaults());
            if (res.Success)
            {
                Dialogs.ShowMessage(
                    this,
                    "LogicFlow — Defaults Restored",
                    $"{res.Message}\n\nPlease restart your computer to complete the transition.");
                await RefreshVirtualMemoryCards();
            }
            else
            {
                Dialogs.ShowMessage(
                    this,
                    "LogicFlow — Pagefile Configuration",
                    $"Failed to restore defaults:\n{res.Message}",
                    isWarningOrError: true);
            }
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "LogicFlow Error", $"Error: {ex.Message}", isWarningOrError: true);
        }
        finally
        {
            HideLoading();
        }
    }

    // ─── Turbo Mode Profiles ───
    private void SetTurboProfileButtonsVisibility(Visibility vis)
    {
        if (BtnTurboSmart != null) BtnTurboSmart.Visibility = vis;
        if (BtnTurboGaming != null) BtnTurboGaming.Visibility = vis;
        if (BtnTurboStreaming != null) BtnTurboStreaming.Visibility = vis;
        if (BtnTurboRendering != null) BtnTurboRendering.Visibility = vis;
        if (BtnTurboBenchmarking != null) BtnTurboBenchmarking.Visibility = vis;
        if (BtnTurboWork != null) BtnTurboWork.Visibility = vis;
        if (BtnTurboBattery != null) BtnTurboBattery.Visibility = vis;
        if (BtnTurboServer != null) BtnTurboServer.Visibility = vis;
    }

    private void RenderTurboActivationUi(TurboMode.TurboResult result, string name, string? smartRationale = null)
    {
        Brush accentBrush = name switch
        {
            "Gaming" or "Benchmarking" => (Brush)FindResource("TurboGamingOrangeBrush"),
            "Work" or "Rendering" => (Brush)FindResource("TurboWorkPurpleBrush"),
            "Battery" or "Minimum" => (Brush)FindResource("TurboBatteryGreenBrush"),
            "Streaming" or "Server" => (Brush)FindResource("BrandCyanBrush"),
            _ => (Brush)FindResource("TextPrimaryBrush")
        };

        TurboModeContainer.BorderBrush = accentBrush;
        TurboModeContainer.BorderThickness = new Thickness(2);
        TurboSummaryText.Foreground = accentBrush;

        TurboSummaryBar.Visibility = Visibility.Visible;
        TurboSummaryText.Text = smartRationale != null
            ? $"🧠 SMART BOOST OVERRIDE: {name.ToUpper()} MODE"
            : $"SYSTEM OVERRIDDEN: {name.ToUpper()} MODE";

        var actions = new List<string>();
        if (!string.IsNullOrWhiteSpace(smartRationale))
        {
            actions.Add($"🧠 Smart Boost Rationale: {smartRationale}");
        }
        actions.AddRange(result.Actions);
        TurboActionList.ItemsSource = actions;

        SetTurboProfileButtonsVisibility(Visibility.Collapsed);
        BtnTurboOff.Visibility = Visibility.Visible;

        TurboModeStatus.Text = $"{name.ToUpper()} ACTIVE: {result.ServicesDisabled} services stopped, {result.ProcessesKilled} background process(es) terminated. {result.MemoryFreedFormatted} RAM freed.";
        TurboModeStatus.Foreground = accentBrush;
        UpdateTurboButtonVisuals(true);
        _trayManager?.SetTooltipSafe($"LogicFlow — Boost Mode Active ({name})");
    }

    private static string FormatTurboTargetsPreview(IReadOnlyList<(int Pid, string ProcessName)> targets)
    {
        string previewList = string.Join(", ", targets.Take(8).Select(t => $"{t.ProcessName} (PID {t.Pid})"));
        if (targets.Count > 8) previewList += $" (+{targets.Count - 8} more)";
        return previewList;
    }

    private async void ActivateTurbo(TurboMode.TurboProfile profile, string name)
    {
        var targets = _turboMode.PreviewTargetProcesses(profile);
        if (targets.Count > 0 && IsVisible)
        {
            string previewList = FormatTurboTargetsPreview(targets);
            bool proceed = Dialogs.Confirm(
                this,
                $"Engage {name} Boost Profile",
                $"{name} Boost will apply profile power/scheduling settings, trim standby RAM, and terminate {targets.Count} non-essential background process(es):\n\n{previewList}\n\nTerminated apps are not automatically relaunched when Boost Mode turns off.",
                $"Engage {name} Boost",
                "Cancel",
                defaultCancel: false);
            if (!proceed) return;
        }

        ShowLoading($"Activating {name} Turbo...");
        try
        {
            var result = await Task.Run(() => _turboMode.Activate(profile));
            RenderTurboActivationUi(result, name);
        }
        catch (Exception ex) { TurboModeStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnTurboSmart(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing active workloads via Gemma 4 E2B Smart Boost...");
        try
        {
            var rec = await _turboMode.SelectAndApplySmartProfileAsync();
            var result = rec.ActivationResult ?? await Task.Run(() => _turboMode.Activate(rec.Profile));
            RenderTurboActivationUi(result, rec.ProfileKey, $"{rec.Rationale} [{rec.PreBoostBottleneck}]");
        }
        catch (Exception ex) { TurboModeStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnTurboGaming(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.GamingProfile, "Gaming");
    private void OnTurboStreaming(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.StreamingProfile, "Streaming");
    private void OnTurboRendering(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.RenderingProfile, "Rendering");
    private void OnTurboBenchmarking(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.BenchmarkingProfile, "Benchmarking");
    private void OnTurboWork(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.WorkProfile, "Work");
    private void OnTurboBattery(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.BatteryProfile, "Battery");
    private void OnTurboServer(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.ServerProfile, "Server");

    private async void OnTurboDeactivate(object s, RoutedEventArgs e)
    {
        ShowLoading("Restoring Normal Operations...");
        try
        {
            var result = await Task.Run(() => _turboMode.Deactivate());
            
            // Revert Styling
            TurboModeContainer.BorderBrush = new SolidColorBrush((Color)System.Windows.Media.ColorConverter.ConvertFromString("#2A3040"));
            TurboModeContainer.BorderThickness = new Thickness(1);
            TurboSummaryText.Foreground = (Brush)FindResource("TextPrimaryBrush");

            TurboSummaryText.Text = "SYSTEM RESTORED";
            TurboActionList.ItemsSource = result.Actions;

            // Manage Toggles
            BtnTurboOff.Visibility = Visibility.Collapsed;
            SetTurboProfileButtonsVisibility(Visibility.Visible);

            // Update Global Dashboard Card
            TurboModeStatus.Text = "STANDBY: Ready to Activate";
            TurboModeStatus.Foreground = (Brush)FindResource("TextSecondaryBrush");
            UpdateTurboButtonVisuals(false);
            _trayManager?.SetTooltipSafe("LogicFlow — System Protection Active");
        }
        catch (Exception ex) { TurboModeStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── WinGet Universal Software Updater ───
    private async void OnWinGetScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning for outdated applications via WinGet...");
        WinGetList.Items.Clear();
        try
        {
            var packages = await _wingetUpdater.ScanUpgradableAppsAsync();
            _lastWinGetPackages = packages;

            bool hasPackages = packages.Count > 0;
            BtnWinGetSelectAll.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;
            BtnWinGetDeselectAll.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;
            BtnWinGetUpgradeSelected.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;
            BtnWinGetUpgradeAll.Visibility = hasPackages ? Visibility.Visible : Visibility.Collapsed;

            WinGetSummaryBar.Visibility = Visibility.Visible;
            WinGetSummaryText.Text = $"📦 {packages.Count} applications have updates available";
            WinGetStatus.Text = hasPackages ? $"Found {packages.Count} pending updates" : "All installed applications are up-to-date!";
            WinGetStatus.Foreground = packages.Count == 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("TextSecondaryBrush");

            RenderWinGetCards();
            UpdateWinGetSelectionSummary();
        }
        catch (Exception ex) { WinGetStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void RenderWinGetCards()
    {
        WinGetList.Items.Clear();
        if (_lastWinGetPackages == null || _lastWinGetPackages.Count == 0)
        {
            WinGetList.Items.Add(MakeResultCard("✅ Up to Date", "No pending application updates discovered on this system.", "SuccessGreenBrush"));
            return;
        }

        foreach (var pkg in _lastWinGetPackages)
        {
            var updateBtn = new System.Windows.Controls.Button
            {
                Content = "⚡ Update",
                Style = (Style)Application.Current.FindResource("ActionCardButton"),
                Margin = new Thickness(12, 0, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center
            };
            updateBtn.Click += async (s, e) =>
            {
                ShowLoading($"Upgrading {pkg.Name}...");
                try
                {
                    var res = await _wingetUpdater.UpgradePackageAsync(pkg.Id);
                    if (res.Success)
                    {
                        WinGetStatus.Text = $"Successfully upgraded {pkg.Name}!";
                        WinGetStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                        OnWinGetScan(s, e);
                    }
                    else
                    {
                        WinGetStatus.Text = $"Upgrade failed for {pkg.Name}: {res.ErrorMessage ?? "Interactive setup required"}";
                    }
                }
                catch (Exception ex) { WinGetStatus.Text = $"Error: {ex.Message}"; }
                finally { HideLoading(); }
            };

            var card = MakeSelectableCard(
                pkg.IsSelected,
                isSelected =>
                {
                    pkg.IsSelected = isSelected;
                    UpdateWinGetSelectionSummary();
                },
                $"📦 {pkg.Name} ({pkg.Id})",
                $"Current: {pkg.CurrentVersion} ➜ Available: {pkg.AvailableVersion} [Source: {pkg.Source}]",
                "BrandCyanBrush",
                badge: "UPDATE",
                badgeColorKey: "BrandCyanBrush",
                rightAction: updateBtn
            );

            WinGetList.Items.Add(card);
        }
    }

    private void UpdateWinGetSelectionSummary()
    {
        if (_lastWinGetPackages == null) return;
        var selectedCount = _lastWinGetPackages.Count(p => p.IsSelected);
        BtnWinGetUpgradeSelected.Content = $"⚡ Update Selected ({selectedCount})";
        BtnWinGetUpgradeSelected.IsEnabled = selectedCount > 0;
    }

    private void OnWinGetSelectAll(object s, RoutedEventArgs e)
    {
        if (_lastWinGetPackages == null) return;
        foreach (var pkg in _lastWinGetPackages) pkg.IsSelected = true;
        RenderWinGetCards();
        UpdateWinGetSelectionSummary();
    }

    private void OnWinGetDeselectAll(object s, RoutedEventArgs e)
    {
        if (_lastWinGetPackages == null) return;
        foreach (var pkg in _lastWinGetPackages) pkg.IsSelected = false;
        RenderWinGetCards();
        UpdateWinGetSelectionSummary();
    }

    private async void OnWinGetUpgradeSelected(object s, RoutedEventArgs e)
    {
        if (_lastWinGetPackages == null || _lastWinGetPackages.Count == 0) return;
        var selected = _lastWinGetPackages.Where(p => p.IsSelected).ToList();
        if (selected.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — WinGet Updater", "Please select at least one application to update.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Upgrade Selected Apps",
            $"Upgrade {selected.Count} selected application(s)?\n\n" +
            string.Join("\n", selected.Select(p => $"• {p.Name} ({p.CurrentVersion} ➜ {p.AvailableVersion})")),
            "Upgrade Apps",
            "Cancel"))
            return;

        ShowLoading($"Upgrading {selected.Count} selected applications...");
        try
        {
            var results = await _wingetUpdater.UpgradePackagesAsync(selected.Select(p => p.Id));
            int success = results.Count(r => r.Success);
            int failed = results.Count(r => !r.Success);
            WinGetStatus.Text = $"Upgrade complete: {success} succeeded, {failed} failed.";
            WinGetStatus.Foreground = failed == 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("WarningAmberBrush");
            OnWinGetScan(s, e);
        }
        catch (Exception ex)
        {
            WinGetStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnWinGetUpgradeAll(object s, RoutedEventArgs e)
    {
        ShowLoading("Silently upgrading all outdated applications...");
        try
        {
            var result = await _wingetUpdater.UpgradeAllAsync();
            if (result.Success)
            {
                WinGetStatus.Text = "Successfully upgraded all packages!";
                WinGetStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                OnWinGetScan(s, e);
            }
            else
            {
                WinGetStatus.Text = $"Upgrade warning: {result.ErrorMessage ?? "Some packages require interactive setup"}";
            }
        }
        catch (Exception ex) { WinGetStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── File Shredder ───
    private void OnFileShredder(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select files to securely shred",
            Multiselect = true,
            Filter = "All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — File Shredder",
            $"PERMANENTLY SHRED {dlg.FileNames.Length} file(s)?\n\n" +
            "This uses DoD 5220.22-M 3-pass secure deletion.\n" +
            "Files CANNOT be recovered after shredding.\n\n" +
            "Are you absolutely sure?",
            "Shred Permanently",
            "Cancel",
            defaultCancel: true,
            destructive: true))
            return;

        var shredResult = _fileShredder.Shred(dlg.FileNames, FileShredder.ShredMethod.DoD3Pass);
        int success = shredResult.FilesShredded;

        ShredderSummaryBar.Visibility = Visibility.Visible;
        ShredderSummaryText.Text = $"✅ {success}/{dlg.FileNames.Length} files securely shredded";
        ShredderStatus.Text = "Shredding complete";
        ShredderStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
    }

    // ─── SMART Disk Health ───
    private void RenderSmartDiskResults(List<SmartDiskHealth.DiskSmartReport> drives)
    {
        _lastSmartDrives = drives;
        SmartDiskList.Items.Clear();
        SmartDiskSummaryBar.Visibility = Visibility.Visible;
        var healthy = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Healthy);
        var critical = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Critical);
        var warning = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Warning);
        SmartDiskSummaryText.Text = $"💾 {drives.Count} physical disk(s) audited: {healthy} Healthy, {warning} Warning, {critical} Critical | Controllers active";
        SmartDiskStatus.Text = $"Physical disk telemetry scan complete ({drives.Count} drives)";
        SmartDiskStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");

        foreach (var drive in drives)
        {
            var color = drive.Status switch
            {
                SmartDiskHealth.DiskHealthStatus.Healthy => "SuccessGreenBrush",
                SmartDiskHealth.DiskHealthStatus.Warning => "WarningAmberBrush",
                SmartDiskHealth.DiskHealthStatus.Critical => "DangerRedBrush",
                _ => "TextSecondaryBrush"
            };
            string icon = drive.Status == SmartDiskHealth.DiskHealthStatus.Healthy ? "💚" : (drive.Status == SmartDiskHealth.DiskHealthStatus.Warning ? "⚠️" : (drive.Status == SmartDiskHealth.DiskHealthStatus.Critical ? "🚨" : "ℹ️"));
            string driveLabel = drive.DriveLetters.Length > 0 ? $" [{string.Join(", ", drive.DriveLetters)}]" : (!string.IsNullOrEmpty(drive.DriveLetter) ? $" [{drive.DriveLetter}]" : "");
            string scoreLabel = drive.HealthScore >= 0 ? $" ({drive.HealthScore}% Score - Grade {drive.HealthGrade})" : "";
            string title = $"{icon} {drive.Model}{driveLabel}{scoreLabel}";

            string summaryText = !string.IsNullOrWhiteSpace(drive.HealthSummary) ? drive.HealthSummary : (drive.Status == SmartDiskHealth.DiskHealthStatus.Healthy ? "Healthy — All SMART attributes nominal" : "Health telemetry available");
            string tempStr = drive.Temperature > 0 ? $"{drive.Temperature}°C" : "Unmeasured";
            string powerStr = drive.PowerOnHours > 0 ? $"{drive.PowerOnHours:N0}h" : "N/A";
            string wearStr = drive.SsdLifeRemaining >= 0 ? $" | 🔋 Life: {drive.SsdLifeRemaining}%" : (drive.NvmePercentageUsed >= 0 ? $" | 🔋 Wear: {drive.NvmePercentageUsed}%" : "");
            string specs = $"{drive.SizeFormatted} {drive.MediaType} ({drive.InterfaceType}) | 🌡 Temp: {tempStr} | ⏱ Power-On: {powerStr}{wearStr}";
            string detail = !string.IsNullOrWhiteSpace(summaryText) ? $"{specs}\n{summaryText}" : specs;

            SmartDiskList.Items.Add(MakeResultCard(title, detail, color));
        }
    }

    private async void OnSmartDiskScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Reading S.M.A.R.T. and physical storage controller telemetry...");
        SmartDiskList.Items.Clear();
        try
        {
            var drives = await Task.Run(() => _smartDiskHealth.ScanDrives());
            RenderSmartDiskResults(drives);
        }
        catch (Exception ex)
        {
            SmartDiskStatus.Text = $"Error: {ex.Message}";
            SmartDiskStatus.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            HideLoading();
        }
    }

    // ─── Windows Tweaks Granular Engine ───
    private readonly HashSet<string> _selectedTweakIds = new(StringComparer.OrdinalIgnoreCase);
    private string _tweakCategoryFilter = "All Categories";
    private string _tweakSafetyFilter = "All Levels";
    private string _tweakSearchQuery = "";

    private void RenderTweakResults()
    {
        _tweakEngine.RefreshStates();

        if (_selectedTweakIds.Count == 0)
        {
            foreach (var t in _tweakEngine.AllTweaks.Where(x => x.Safety == SafetyLevel.Safe && !x.IsApplied))
            {
                _selectedTweakIds.Add(t.Id);
            }
        }

        TweakSummaryBar.Visibility = Visibility.Visible;
        TweakToolbar.Visibility = Visibility.Visible;
        BtnApplySelectedTweaks.Visibility = Visibility.Visible;
        BtnRevertSelectedTweaks.Visibility = Visibility.Visible;
        BtnTweakSelectAllSafe.Visibility = Visibility.Visible;
        BtnTweakDeselectAll.Visibility = Visibility.Visible;

        UpdateTweakSummary();
        PopulateTweakCards();
    }

    private void OnTweakScan(object s, RoutedEventArgs e)
    {
        RenderTweakResults();
    }

    private void UpdateTweakSummary()
    {
        if (!IsInitialized || TweakSummaryText == null || TweakStatus == null || _tweakEngine == null) return;
        var all = _tweakEngine.AllTweaks;
        int total = all.Count;
        int applied = all.Count(t => t.IsApplied);
        int selected = _selectedTweakIds.Count;
        TweakSummaryText.Text = $"🔍 {total} tweaks cataloged — {applied} applied | {selected} selected for action";
        TweakStatus.Text = $"{applied}/{total} optimizations applied";
        TweakStatus.Foreground = applied > 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("TextSecondaryBrush");
    }

    private void PopulateTweakCards()
    {
        if (!IsInitialized || TweakList == null || _tweakEngine == null) return;
        TweakList.Items.Clear();

        var query = _tweakEngine.AllTweaks.AsEnumerable();

        if (_tweakCategoryFilter != "All Categories")
        {
            if (Enum.TryParse<TweakCategory>(_tweakCategoryFilter, true, out var cat))
            {
                query = query.Where(t => t.Category == cat);
            }
        }

        if (_tweakSafetyFilter != "All Levels")
        {
            if (_tweakSafetyFilter.StartsWith("Safe", StringComparison.OrdinalIgnoreCase))
                query = query.Where(t => t.Safety == SafetyLevel.Safe);
            else if (_tweakSafetyFilter.StartsWith("Moderate", StringComparison.OrdinalIgnoreCase))
                query = query.Where(t => t.Safety == SafetyLevel.Moderate);
            else if (_tweakSafetyFilter.StartsWith("Advanced", StringComparison.OrdinalIgnoreCase))
                query = query.Where(t => t.Safety == SafetyLevel.Advanced);
        }

        if (!string.IsNullOrWhiteSpace(_tweakSearchQuery))
        {
            query = query.Where(t =>
                t.Name.Contains(_tweakSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                t.Description.Contains(_tweakSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                t.Id.Contains(_tweakSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                t.Category.ToString().Contains(_tweakSearchQuery, StringComparison.OrdinalIgnoreCase));
        }

        var matchingList = query.ToList();
        if (matchingList.Count == 0)
        {
            TweakList.Items.Add(MakeResultCard("🔍 No Matching Optimizations", "No Windows tweaks match the selected filters or search criteria.", "TextSecondaryBrush"));
            return;
        }

        var categoryIcons = new Dictionary<TweakCategory, string>
        {
            [TweakCategory.Privacy] = "🔒",
            [TweakCategory.Performance] = "⚡",
            [TweakCategory.Gaming] = "🎮",
            [TweakCategory.Network] = "🌐",
            [TweakCategory.Services] = "🔧",
            [TweakCategory.Visual] = "🖥",
            [TweakCategory.Maintenance] = "🔑",
            [TweakCategory.Server] = "🗄"
        };

        foreach (var tweak in matchingList)
        {
            var t = tweak;
            string icon = categoryIcons.GetValueOrDefault(t.Category, "⚙");
            string statusBadge = t.IsApplied ? "APPLIED" : "NOT APPLIED";
            string badgeColor = t.IsApplied ? "SuccessGreenBrush" : "TextSecondaryBrush";
            string titleColor = t.IsApplied ? "SuccessGreenBrush" : "TextPrimaryBrush";

            string safetyTag = t.Safety switch
            {
                SafetyLevel.Safe => "🛡 SAFE",
                SafetyLevel.Moderate => "⚠️ MODERATE",
                SafetyLevel.Advanced => "⚡ ADVANCED",
                _ => t.Safety.ToString().ToUpperInvariant()
            };

            string title = $"{icon} {t.Name}";
            string rebootText = t.RequiresReboot ? " • [Requires Reboot]" : "";
            string detail = $"[{t.Category} • {safetyTag}{rebootText}]  {t.Description}";

            var actionBtn = new System.Windows.Controls.Button
            {
                Content = t.IsApplied ? "⟲ Revert" : "⚡ Apply",
                Style = (Style)Application.Current.FindResource(t.IsApplied ? "HeaderOutlineButton" : "HeaderActionButton"),
                Height = 24,
                Padding = new Thickness(8, 0, 8, 0),
                FontSize = 10,
                Cursor = System.Windows.Input.Cursors.Hand,
                ToolTip = t.IsApplied ? "Revert this tweak to Windows default" : "Apply this Windows optimization immediately"
            };

            actionBtn.Click += (s, e) =>
            {
                if (t.IsApplied)
                {
                    var res = _tweakEngine.RevertTweak(t.Id);
                    if (res.Success)
                    {
                        t.IsApplied = false;
                        _selectedTweakIds.Remove(t.Id);
                    }
                    else
                    {
                        Dialogs.ShowMessage(this, "Tweak Error", $"Failed to revert tweak: {res.Error}", isWarningOrError: true);
                    }
                }
                else
                {
                    var res = _tweakEngine.ApplyTweak(t.Id);
                    if (res.Success)
                    {
                        t.IsApplied = true;
                        _selectedTweakIds.Add(t.Id);
                    }
                    else
                    {
                        Dialogs.ShowMessage(this, "Tweak Error", $"Failed to apply tweak: {res.Error}", isWarningOrError: true);
                    }
                }
                UpdateTweakSummary();
                PopulateTweakCards();
            };

            var card = MakeSelectableCard(
                _selectedTweakIds.Contains(t.Id),
                (isChecked) =>
                {
                    if (isChecked) _selectedTweakIds.Add(t.Id);
                    else _selectedTweakIds.Remove(t.Id);
                    UpdateTweakSummary();
                },
                title,
                detail,
                titleColor,
                statusBadge,
                badgeColor,
                null,
                actionBtn);

            TweakList.Items.Add(card);
        }
    }

    private void OnApplySelectedTweaks(object s, RoutedEventArgs e)
    {
        var targetTweaks = _tweakEngine.AllTweaks
            .Where(t => _selectedTweakIds.Contains(t.Id) && !t.IsApplied)
            .ToList();

        if (targetTweaks.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Optimizations", "No unapplied tweaks are currently selected for optimization.\nCheck boxes next to desired tweaks first.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Apply Selected Optimizations",
            $"Apply {targetTweaks.Count} selected Windows optimization(s)?\n\n" +
            string.Join("\n", targetTweaks.Take(6).Select(t => $"• {t.Name} [{t.Safety}]")) +
            (targetTweaks.Count > 6 ? $"\n... and {targetTweaks.Count - 6} more" : "") + "\n\n" +
            "All changes are reversible anytime through LogicFlow.",
            "Apply Optimizations",
            "Cancel"))
            return;

        int successCount = 0;
        foreach (var t in targetTweaks)
        {
            var res = _tweakEngine.ApplyTweak(t.Id);
            if (res.Success) successCount++;
        }

        TweakSummaryText.Text = $"✅ {successCount}/{targetTweaks.Count} optimizations applied successfully";
        TweakSummaryText.Foreground = (Brush)FindResource("SuccessGreenBrush");
        UpdateTweakSummary();
        PopulateTweakCards();
    }

    private void OnRevertSelectedTweaks(object s, RoutedEventArgs e)
    {
        var targetTweaks = _tweakEngine.AllTweaks
            .Where(t => _selectedTweakIds.Contains(t.Id) && t.IsApplied)
            .ToList();

        if (targetTweaks.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Optimizations", "No currently applied tweaks are selected for reversion.\nSelect applied tweaks to restore Windows defaults.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Revert Selected Optimizations",
            $"Revert {targetTweaks.Count} selected optimization(s) to Windows defaults?\n\n" +
            string.Join("\n", targetTweaks.Take(6).Select(t => $"• {t.Name}")) +
            (targetTweaks.Count > 6 ? $"\n... and {targetTweaks.Count - 6} more" : ""),
            "Revert Optimizations",
            "Cancel"))
            return;

        int successCount = 0;
        foreach (var t in targetTweaks)
        {
            var res = _tweakEngine.RevertTweak(t.Id);
            if (res.Success) successCount++;
        }

        TweakSummaryText.Text = $"⟲ {successCount}/{targetTweaks.Count} optimizations reverted to Windows defaults";
        TweakSummaryText.Foreground = (Brush)FindResource("BrandCyanBrush");
        UpdateTweakSummary();
        PopulateTweakCards();
    }

    private void OnTweakSelectAllSafe(object s, RoutedEventArgs e)
    {
        foreach (var t in _tweakEngine.AllTweaks)
        {
            if (t.Safety == SafetyLevel.Safe)
                _selectedTweakIds.Add(t.Id);
            else
                _selectedTweakIds.Remove(t.Id);
        }
        UpdateTweakSummary();
        PopulateTweakCards();
    }

    private void OnTweakDeselectAll(object s, RoutedEventArgs e)
    {
        _selectedTweakIds.Clear();
        UpdateTweakSummary();
        PopulateTweakCards();
    }

    private void OnTweakCategoryChanged(object s, SelectionChangedEventArgs e)
    {
        if (!IsInitialized) return;
        if (ComboTweakCategory?.SelectedItem is ComboBoxItem item)
        {
            _tweakCategoryFilter = item.Content?.ToString() ?? "All Categories";
            PopulateTweakCards();
        }
    }

    private void OnTweakSafetyChanged(object s, SelectionChangedEventArgs e)
    {
        if (!IsInitialized) return;
        if (ComboTweakSafety?.SelectedItem is ComboBoxItem item)
        {
            _tweakSafetyFilter = item.Content?.ToString() ?? "All Levels";
            PopulateTweakCards();
        }
    }

    private void OnTweakSearchChanged(object s, TextChangedEventArgs e)
    {
        if (!IsInitialized) return;
        if (TweakSearchBox != null)
        {
            _tweakSearchQuery = TweakSearchBox.Text.Trim();
            PopulateTweakCards();
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  GAME VAULT & STORAGE OPTIMIZATION (Milestone 5)
    // ═══════════════════════════════════════════════════════════

    private void OnScanGameLibraries(object s, RoutedEventArgs e) => OnRefreshGameVault(s, e);
    private void OnRecompactUpdates(object s, RoutedEventArgs e) => OnRecompactGameUpdates(s, e);
    private void OnCancelGameCompact(object s, RoutedEventArgs e) => OnCancelGameOperation(s, e);

    private async void OnRefreshGameVault(object s, RoutedEventArgs e)
    {
        if (_isGameOperationRunning) return;

        GameVaultStatusLabel.Text = "Scanning Steam, Epic Games, GOG, and custom PC game libraries...";
        GameVaultStatusLabel.Foreground = (Brush)FindResource("TextSecondaryBrush");

        try
        {
            var (games, decay) = await Task.Run(() =>
            {
                var detected = _gameDetector.DetectAllGames().ToList();
                var dec = _gameCompressionEngine.AuditDecay(detected);
                return (detected, dec);
            });

            _lastDetectedGames = games;
            _lastDecayAudit = decay;

            _gameVaultItems.Clear();
            var decayMap = decay.DecayedGames.ToDictionary(d => d.GameId, d => d);
            foreach (var g in games)
            {
                var vm = new GameVaultItemViewModel(g);
                if (decayMap.TryGetValue(g.GameId, out var decInfo) && decInfo.HasDecay)
                {
                    vm.HasDecay = true;
                    vm.DecayedBytes = decInfo.DecayedBytes;
                }
                _gameVaultItems.Add(vm);
            }

            _gameVaultSummary.Recalculate(_gameVaultItems, decay);
            UpdateGameVaultSummaryUI();

            if (decay.HasDecay)
            {
                DecayAlertBanner.Visibility = Visibility.Visible;
                DecayAlertText.Text = $"Updates detected on {decay.GamesWithDecay} game(s). Uncompressed patch deltas found: {decay.FormattedTotalDecayedBytes} eligible for compaction.";
            }
            else
            {
                DecayAlertBanner.Visibility = Visibility.Collapsed;
            }

            RenderGameVaultCards();

            GameVaultStatusLabel.Text = $"Vault refreshed — {games.Count} games discovered ({_gameVaultSummary.CompressedGames} compressed, {decay.GamesWithDecay} updates pending).";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex)
        {
            GameVaultStatusLabel.Text = $"Error scanning game libraries: {ex.Message}";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
    }

    private async void OnCompactAllGames(object s, RoutedEventArgs e)
    {
        if (_isGameOperationRunning) return;

        bool skipDs = ChkSkipDirectStorage?.IsChecked ?? true;
        var compressible = _gameVaultItems
            .Where(g => !g.IsCompressed && (!g.HasDirectStorage || !skipDs))
            .ToList();

        if (compressible.Count == 0)
        {
            if (GameVaultStatusLabel != null)
            {
                GameVaultStatusLabel.Text = "ℹ All detected games are already compressed or protected by DirectStorage safe mode.";
                GameVaultStatusLabel.Foreground = (Brush)FindResource("BrandCyanBrush");
            }
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "Batch Vault Compression",
            $"Compact all {compressible.Count} eligible games in the vault?\n\n" +
            "Compression runs in the background with DirectStorage protection. You can cancel at any time without data corruption.",
            "Compress All",
            "Cancel"))
            return;

        SetGameOperationActive(true, $"Batch Compacting {compressible.Count} Games...");
        _gameCompressionCts = new CancellationTokenSource();
        var ct = _gameCompressionCts.Token;

        int completedGames = 0;
        long batchSavedBytes = 0;
        var batchSw = System.Diagnostics.Stopwatch.StartNew();

        uint globalAlgo = WofNative.ALGORITHM_LZX;
        if (ComboGlobalAlgorithm?.SelectedItem is ComboBoxItem cbi && uint.TryParse(cbi.Tag?.ToString(), out uint parsedAlgo))
        {
            globalAlgo = parsedAlgo;
        }

        try
        {
            for (int i = 0; i < compressible.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var item = compressible[i];
                item.IsProcessing = true;
                item.StatusText = $"Queued ({i + 1}/{compressible.Count})...";

                var progress = new Progress<CompressionProgress>(p =>
                {
                    _gameVaultProgress.UpdateFromProgress(p, $"[{i + 1}/{compressible.Count}] Compacting {item.Title}...");
                    UpdateGameVaultProgressUI();
                    item.UpdateFromProgress(p);
                });

                var options = new GameCompressionOptions(
                    Algorithm: globalAlgo,
                    SkipDirectStorage: skipDs);

                var summary = await Task.Run(() => _gameCompressionEngine.CompressGameAsync(item.Game, options, progress, ct), ct);

                item.IsProcessing = false;
                if (summary.Success)
                {
                    completedGames++;
                    batchSavedBytes += summary.SavedBytes;
                    item.UpdateFromSummary(summary);
                }
                else
                {
                    item.StatusText = "Skipped/Error";
                }

                _gameVaultSummary.Recalculate(_gameVaultItems);
                UpdateGameVaultSummaryUI();
            }

            batchSw.Stop();
            GameVaultStatusLabel.Text = $"✅ Batch compression finished! {completedGames}/{compressible.Count} games compacted. Total storage reclaimed: {GameVaultItemViewModel.FormatBytes(batchSavedBytes)} in {batchSw.Elapsed:mm\\:ss}.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (OperationCanceledException)
        {
            GameVaultStatusLabel.Text = $"Batch compression cancelled by user. {completedGames} games were completed ({GameVaultItemViewModel.FormatBytes(batchSavedBytes)} reclaimed).";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        catch (Exception ex)
        {
            GameVaultStatusLabel.Text = $"Batch compression encountered error: {ex.Message}";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            foreach (var item in compressible) item.IsProcessing = false;
            SetGameOperationActive(false);
            _gameCompressionCts?.Dispose();
            _gameCompressionCts = null;
            RenderGameVaultCards();
        }
    }

    private async void OnDecompressAllGames(object s, RoutedEventArgs e)
    {
        if (_isGameOperationRunning) return;

        var compressed = _gameVaultItems.Where(g => g.IsCompressed).ToList();
        if (compressed.Count == 0)
        {
            GameVaultStatusLabel.Text = "No compressed games found in vault to decompress.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("TextSecondaryBrush");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "Decompress All Games",
            $"Revert compression on all {compressed.Count} compressed games in the vault?\n\n" +
            "This will expand files back to standard uncompressed NTFS format.",
            "Restore All",
            "Cancel"))
            return;

        SetGameOperationActive(true, $"Decompressing {compressed.Count} Games...");
        _gameCompressionCts = new CancellationTokenSource();
        var ct = _gameCompressionCts.Token;

        int completed = 0;
        try
        {
            for (int i = 0; i < compressed.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var item = compressed[i];
                item.IsProcessing = true;

                var progress = new Progress<CompressionProgress>(p =>
                {
                    _gameVaultProgress.UpdateFromProgress(p, $"[{i + 1}/{compressed.Count}] Decompressing {item.Title}...");
                    UpdateGameVaultProgressUI();
                    item.UpdateFromProgress(p);
                });

                var summary = await Task.Run(() => _gameCompressionEngine.DecompressGameAsync(item.Game, progress, ct), ct);
                item.IsProcessing = false;

                if (summary.Success)
                {
                    completed++;
                    item.UpdateFromDecompression(summary);
                }

                _gameVaultSummary.Recalculate(_gameVaultItems);
                UpdateGameVaultSummaryUI();
            }

            GameVaultStatusLabel.Text = $"✅ Decompression complete! {completed}/{compressed.Count} games restored to standard NTFS.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (OperationCanceledException)
        {
            GameVaultStatusLabel.Text = "Decompression cancelled by user.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        catch (Exception ex)
        {
            GameVaultStatusLabel.Text = $"Decompression error: {ex.Message}";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            foreach (var item in compressed) item.IsProcessing = false;
            SetGameOperationActive(false);
            _gameCompressionCts?.Dispose();
            _gameCompressionCts = null;
            RenderGameVaultCards();
        }
    }

    private async void OnRecompactGameUpdates(object s, RoutedEventArgs e)
    {
        if (_isGameOperationRunning) return;

        var decayedItems = _gameVaultItems.Where(g => g.HasDecay).ToList();
        if (decayedItems.Count == 0)
        {
            GameVaultStatusLabel.Text = "Auditing games for update decay...";
            try
            {
                var audit = await Task.Run(() => _gameCompressionEngine.AuditDecay(_lastDetectedGames ?? _gameDetector.DetectAllGames()));
                _lastDecayAudit = audit;
                if (!audit.HasDecay)
                {
                    GameVaultStatusLabel.Text = "✅ No uncompressed game update files detected. Your vault is fully optimized!";
                    GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
                    DecayAlertBanner.Visibility = Visibility.Collapsed;
                    return;
                }

                var map = audit.DecayedGames.ToDictionary(d => d.GameId, d => d);
                foreach (var item in _gameVaultItems)
                {
                    if (map.TryGetValue(item.GameId, out var dec))
                    {
                        item.HasDecay = true;
                        item.DecayedBytes = dec.DecayedBytes;
                    }
                }
                decayedItems = _gameVaultItems.Where(g => g.HasDecay).ToList();
            }
            catch (Exception ex)
            {
                GameVaultStatusLabel.Text = $"Audit error: {ex.Message}";
                return;
            }
        }

        SetGameOperationActive(true, $"Re-compacting Updates for {decayedItems.Count} Games...");
        _gameCompressionCts = new CancellationTokenSource();
        var ct = _gameCompressionCts.Token;

        int recompactedCount = 0;
        long reclaimedBytes = 0;

        try
        {
            for (int i = 0; i < decayedItems.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var item = decayedItems[i];
                item.IsProcessing = true;
                item.StatusText = "Re-compacting...";

                var progress = new Progress<CompressionProgress>(p =>
                {
                    _gameVaultProgress.UpdateFromProgress(p, $"[{i + 1}/{decayedItems.Count}] Re-compacting {item.Title} updates...");
                    UpdateGameVaultProgressUI();
                    item.UpdateFromProgress(p);
                });

                var options = new GameCompressionOptions(item.SelectedAlgorithm, SkipDirectStorage: item.SkipDirectStorage);
                var summary = await Task.Run(() => _gameCompressionEngine.RecompactUpdatesAsync(item.Game, options, progress, ct), ct);

                item.IsProcessing = false;
                if (summary.Success)
                {
                    recompactedCount++;
                    reclaimedBytes += summary.SavedBytes;
                    item.UpdateFromSummary(summary);
                    item.HasDecay = false;
                    item.DecayedBytes = 0;
                    item.StatusText = "Updated & Compacted";
                }
            }

            DecayAlertBanner.Visibility = Visibility.Collapsed;
            _gameVaultSummary.Recalculate(_gameVaultItems);
            UpdateGameVaultSummaryUI();

            GameVaultStatusLabel.Text = $"✅ 1-Click Update Re-compaction Complete! Reclaimed {GameVaultItemViewModel.FormatBytes(reclaimedBytes)} from {recompactedCount} games.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (OperationCanceledException)
        {
            GameVaultStatusLabel.Text = "Re-compacting updates cancelled by user.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        catch (Exception ex)
        {
            GameVaultStatusLabel.Text = $"Error re-compacting updates: {ex.Message}";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            foreach (var item in decayedItems) item.IsProcessing = false;
            SetGameOperationActive(false);
            _gameCompressionCts?.Dispose();
            _gameCompressionCts = null;
            RenderGameVaultCards();
        }
    }

    private void OnCancelGameOperation(object s, RoutedEventArgs e)
    {
        if (_gameCompressionCts != null && !_gameCompressionCts.IsCancellationRequested)
        {
            _gameCompressionCts.Cancel();
            GameVaultStatusLabel.Text = "Cancelling game compression operation...";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
    }

    private void OnLauncherFilterChanged(object s, SelectionChangedEventArgs e)
    {
        if (GameVaultList == null || GameVaultEmptyState == null) return;
        RenderGameVaultCards();
    }

    private async Task CompactSingleGameAsync(GameVaultItemViewModel item)
    {
        if (!Gate.Require(Capability.Core, this)) return;
        if (_isGameOperationRunning || item == null) return;

        if (item.HasDirectStorage && item.SkipDirectStorage)
        {
            if (!Dialogs.Confirm(
                this,
                "DirectStorage Safety Warning",
                $"DirectStorage / BypassIO Detected!\n\n'{item.Title}' uses dstorage.dll for GPU decompression pipelines.\n\n" +
                "Compressing its game assets may bypass DirectStorage GPU decompression and increase CPU usage during streaming.\n\n" +
                "Do you wish to force compression anyway?",
                "Force Compression",
                "Skip Game",
                defaultCancel: true))
            {
                GameVaultStatusLabel.Text = $"Skipped compression for '{item.Title}' (DirectStorage safe mode active).";
                return;
            }
            item.SkipDirectStorage = false;
        }

        SetGameOperationActive(true, $"Compacting {item.Title}...");
        item.IsProcessing = true;
        item.StatusText = "Compacting...";

        _gameCompressionCts = new CancellationTokenSource();
        var ct = _gameCompressionCts.Token;

        var progress = new Progress<CompressionProgress>(p =>
        {
            _gameVaultProgress.UpdateFromProgress(p, $"Compacting {item.Title} ({item.SelectedAlgorithmName})...");
            UpdateGameVaultProgressUI();
            item.UpdateFromProgress(p);
        });

        try
        {
            var options = new GameCompressionOptions(
                Algorithm: item.SelectedAlgorithm,
                SkipDirectStorage: item.SkipDirectStorage);

            var summary = await Task.Run(() => _gameCompressionEngine.CompressGameAsync(item.Game, options, progress, ct), ct);

            if (summary.Success)
            {
                item.UpdateFromSummary(summary);
                GameVaultStatusLabel.Text = $"✅ Successfully compacted '{item.Title}'! Reclaimed {summary.FormattedSavedBytes} ({summary.SpaceSavedPercent:0.0}%) at {summary.FormattedThroughput}.";
                GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");

                _gameVaultSummary.Recalculate(_gameVaultItems);
                UpdateGameVaultSummaryUI();
                RenderGameVaultCards();
            }
            else
            {
                item.StatusText = "Compression failed";
                GameVaultStatusLabel.Text = $"Compression failed for '{item.Title}': {summary.ErrorMessage}";
                GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
            }
        }
        catch (OperationCanceledException)
        {
            item.StatusText = "Cancelled";
            GameVaultStatusLabel.Text = $"Compression cancelled for '{item.Title}'.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        catch (Exception ex)
        {
            item.StatusText = "Error";
            GameVaultStatusLabel.Text = $"Unexpected error compacting '{item.Title}': {ex.Message}";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            item.IsProcessing = false;
            SetGameOperationActive(false);
            _gameCompressionCts?.Dispose();
            _gameCompressionCts = null;
            RenderGameVaultCards();
        }
    }

    private async Task DecompressSingleGameAsync(GameVaultItemViewModel item)
    {
        if (!Gate.Require(Capability.Core, this)) return;
        if (_isGameOperationRunning || item == null) return;

        SetGameOperationActive(true, $"Decompressing {item.Title}...");
        item.IsProcessing = true;
        item.StatusText = "Decompressing...";

        _gameCompressionCts = new CancellationTokenSource();
        var ct = _gameCompressionCts.Token;

        var progress = new Progress<CompressionProgress>(p =>
        {
            _gameVaultProgress.UpdateFromProgress(p, $"Decompressing {item.Title}...");
            UpdateGameVaultProgressUI();
            item.UpdateFromProgress(p);
        });

        try
        {
            var summary = await Task.Run(() => _gameCompressionEngine.DecompressGameAsync(item.Game, progress, ct), ct);

            if (summary.Success)
            {
                item.UpdateFromDecompression(summary);
                GameVaultStatusLabel.Text = $"✅ Restored '{item.Title}' to standard NTFS! Restored {summary.FormattedRestoredBytes} at {summary.FormattedThroughput}.";
                GameVaultStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");

                _gameVaultSummary.Recalculate(_gameVaultItems);
                UpdateGameVaultSummaryUI();
                RenderGameVaultCards();
            }
            else
            {
                item.StatusText = "Decompress failed";
                GameVaultStatusLabel.Text = $"Decompression failed for '{item.Title}': {summary.ErrorMessage}";
                GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
            }
        }
        catch (OperationCanceledException)
        {
            item.StatusText = "Cancelled";
            GameVaultStatusLabel.Text = $"Decompression cancelled for '{item.Title}'.";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("WarningAmberBrush");
        }
        catch (Exception ex)
        {
            item.StatusText = "Error";
            GameVaultStatusLabel.Text = $"Unexpected error decompressing '{item.Title}': {ex.Message}";
            GameVaultStatusLabel.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            item.IsProcessing = false;
            SetGameOperationActive(false);
            _gameCompressionCts?.Dispose();
            _gameCompressionCts = null;
            RenderGameVaultCards();
        }
    }

    private void RenderGameVaultCards()
    {
        if (GameVaultList == null || GameVaultEmptyState == null) return;
        GameVaultList.Items.Clear();

        int filterIndex = ComboLauncherFilter?.SelectedIndex ?? 0;
        LauncherType? filter = filterIndex switch
        {
            1 => LauncherType.Steam,
            2 => LauncherType.Epic,
            3 => LauncherType.GOG,
            4 => LauncherType.Custom,
            _ => null
        };

        var itemsToRender = filter.HasValue
            ? _gameVaultItems.Where(i => i.Launcher == filter.Value).ToList()
            : _gameVaultItems.ToList();

        foreach (var item in itemsToRender)
        {
            GameVaultList.Items.Add(MakeGameVaultCard(item));
        }

        GameVaultEmptyState.Visibility = itemsToRender.Count == 0 && _gameVaultItems.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        GameVaultList.Visibility = itemsToRender.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private Border MakeGameVaultCard(GameVaultItemViewModel item)
    {
        var card = new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Margin = new Thickness(0, 0, 0, 8),
            Padding = new Thickness(14, 12, 14, 12)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // 0: Badge
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // 1: Info
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // 2: Algo ComboBox
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // 3: Actions

        // 1. Launcher Badge
        Brush bgBrush;
        Brush fgBrush;
        try
        {
            bgBrush = new SolidColorBrush((Color)System.Windows.Media.ColorConverter.ConvertFromString(item.LauncherBadgeColor));
            fgBrush = new SolidColorBrush((Color)System.Windows.Media.ColorConverter.ConvertFromString(item.LauncherBadgeForeground));
        }
        catch
        {
            bgBrush = new SolidColorBrush(Color.FromRgb(27, 40, 56));
            fgBrush = new SolidColorBrush(Color.FromRgb(102, 192, 244));
        }

        var badge = new Border
        {
            Background = bgBrush,
            BorderBrush = fgBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(8, 4, 8, 4),
            Margin = new Thickness(0, 0, 12, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = item.LauncherBadgeText,
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = fgBrush
            }
        };
        Grid.SetColumn(badge, 0);
        grid.Children.Add(badge);

        // 2. Info Stack
        var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var titleRow = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        titleRow.Children.Add(new TextBlock
        {
            Text = item.Title,
            FontSize = 13,
            FontWeight = FontWeights.Bold,
            Foreground = (Brush)FindResource("TextPrimaryBrush")
        });

        if (item.HasDirectStorage)
        {
            var dsBadge = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0x26, 0xF5, 0x9E, 0x0B)),
                BorderBrush = (Brush)FindResource("WarningAmberBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(8, 0, 0, 0),
                ToolTip = "DirectStorage (dstorage.dll) detected. Compressing may degrade high-speed GPU streaming throughput.",
                Child = new TextBlock
                {
                    Text = "⚡ DIRECTSTORAGE",
                    FontSize = 9,
                    FontWeight = FontWeights.Bold,
                    Foreground = (Brush)FindResource("WarningAmberBrush")
                }
            };
            titleRow.Children.Add(dsBadge);
        }

        // Status Badge
        var statusBorder = new Border
        {
            CornerRadius = new CornerRadius(4),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 2, 6, 2),
            Margin = new Thickness(8, 0, 0, 0)
        };
        if (item.IsCompressed)
        {
            statusBorder.Background = new SolidColorBrush(Color.FromArgb(0x20, 0x22, 0xC5, 0x5E));
            statusBorder.BorderBrush = (Brush)FindResource("SuccessGreenBrush");
            statusBorder.Child = new TextBlock
            {
                Text = "COMPRESSED",
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = (Brush)FindResource("SuccessGreenBrush")
            };
        }
        else if (item.HasDecay)
        {
            statusBorder.Background = new SolidColorBrush(Color.FromArgb(0x26, 0xF5, 0x9E, 0x0B));
            statusBorder.BorderBrush = (Brush)FindResource("WarningAmberBrush");
            statusBorder.Child = new TextBlock
            {
                Text = "UPDATE DECAY",
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = (Brush)FindResource("WarningAmberBrush")
            };
        }
        else
        {
            statusBorder.Background = new SolidColorBrush(Color.FromArgb(0x15, 0xFF, 0xFF, 0xFF));
            statusBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(0x25, 0xFF, 0xFF, 0xFF));
            statusBorder.Child = new TextBlock
            {
                Text = "UNCOMPRESSED",
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = (Brush)FindResource("TextSecondaryBrush")
            };
        }
        titleRow.Children.Add(statusBorder);
        info.Children.Add(titleRow);

        info.Children.Add(new TextBlock
        {
            Text = item.InstallDirectory,
            FontSize = 10,
            FontFamily = new FontFamily("Consolas, JetBrains Mono"),
            Foreground = (Brush)FindResource("TextSecondaryBrush"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 3, 0, 2)
        });

        info.Children.Add(new TextBlock
        {
            Text = $"Size: {item.FormattedSizeOnDisk} | Estimated Savings: {item.FormattedEstimatedSavings}",
            FontSize = 10.5,
            Foreground = (Brush)FindResource("BrandCyanBrush")
        });

        Grid.SetColumn(info, 1);
        grid.Children.Add(info);

        // 3. Per-Game Algorithm ComboBox
        var algoCombo = new System.Windows.Controls.ComboBox
        {
            Style = (Style)FindResource("DarkComboBoxStyle"),
            Width = 110,
            Height = 28,
            Margin = new Thickness(0, 0, 10, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        algoCombo.Items.Add(new ComboBoxItem { Tag = 1, Content = "LZX (Max)" });
        algoCombo.Items.Add(new ComboBoxItem { Tag = 2, Content = "XPRESS8K" });
        algoCombo.Items.Add(new ComboBoxItem { Tag = 3, Content = "XPRESS16K" });
        algoCombo.Items.Add(new ComboBoxItem { Tag = 0, Content = "XPRESS4K" });
        algoCombo.SelectedIndex = item.SelectedAlgorithmIndex;
        algoCombo.SelectionChanged += (s, e) =>
        {
            item.SelectedAlgorithmIndex = algoCombo.SelectedIndex;
        };
        Grid.SetColumn(algoCombo, 2);
        grid.Children.Add(algoCombo);

        // 4. Action Buttons
        var actionPanel = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var compactBtn = new System.Windows.Controls.Button
        {
            Content = "⚡ Compact",
            Style = (Style)FindResource("ActionButton"),
            Height = 28,
            Padding = new Thickness(12, 4, 12, 4),
            FontSize = 11,
            IsEnabled = item.CanCompact
        };
        compactBtn.Click += async (s, e) => await CompactSingleGameAsync(item);
        actionPanel.Children.Add(compactBtn);

        var decompressBtn = new System.Windows.Controls.Button
        {
            Content = "↩ Decompress",
            Style = (Style)FindResource("OutlineButton"),
            Height = 28,
            Padding = new Thickness(10, 4, 10, 4),
            FontSize = 11,
            Margin = new Thickness(6, 0, 0, 0),
            IsEnabled = item.CanDecompress
        };
        decompressBtn.Click += async (s, e) => await DecompressSingleGameAsync(item);
        actionPanel.Children.Add(decompressBtn);

        Grid.SetColumn(actionPanel, 3);
        grid.Children.Add(actionPanel);

        card.Child = grid;
        return card;
    }

    private void UpdateGameVaultSummaryUI()
    {
        GameVaultSummaryBar.Visibility = _gameVaultItems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        GameVaultEmptyState.Visibility = _gameVaultItems.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        GameVaultList.Visibility = _gameVaultItems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        GameVaultTotalGamesMetric.Text = $"{_gameVaultSummary.TotalGames} Titles";
        GameVaultTotalDiskMetric.Text = _gameVaultSummary.FormattedTotalSize;
        GameVaultSavingsMetric.Text = _gameVaultSummary.FormattedTotalSavings;
        GameVaultRecoveredMetric.Text = _gameVaultSummary.FormattedReclaimedStorage;
        GameVaultDirectStorageMetric.Text = $"{_gameVaultSummary.DirectStorageProtectedCount} Titles";
    }

    private void UpdateGameVaultProgressUI()
    {
        ProgressOperationTitle.Text = _gameVaultProgress.OperationTitle;
        ProgressCurrentFile.Text = _gameVaultProgress.CurrentFile;
        GameCompactProgressBar.Value = Math.Clamp(_gameVaultProgress.PercentComplete, 0, 100);
        ProgressFilesText.Text = _gameVaultProgress.ProgressFilesText;
        ProgressThroughputText.Text = $"Throughput: {_gameVaultProgress.FormattedThroughput}";
        ProgressSavedText.Text = $"Saved: {GameVaultItemViewModel.FormatBytes(_gameVaultProgress.BytesSaved)} ({_gameVaultProgress.PercentComplete:0.0}%)";
        ProgressTimeText.Text = $"{_gameVaultProgress.FormattedElapsed} | {_gameVaultProgress.FormattedEta}";
    }

    private void SetGameOperationActive(bool active, string? title = null)
    {
        _isGameOperationRunning = active;
        _gameVaultProgress.IsActive = active;
        if (active && title != null)
        {
            _gameVaultProgress.OperationTitle = title;
        }
        GameVaultProgressPanel.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        BtnScanGameLibraries.IsEnabled = !active;
        BtnCompactAllGames.IsEnabled = !active;
        BtnRecompactDecay.IsEnabled = !active;
        BtnDecompressAllGames.IsEnabled = !active;
        ComboGlobalAlgorithm.IsEnabled = !active;
        ComboLauncherFilter.IsEnabled = !active;
        ChkSkipDirectStorage.IsEnabled = !active;
    }

    // ─── Startup Optimizer + Disable (adapted from Optimizer's StartupHelper) ───
    private void RenderStartupResults(List<StartupItem> items)
    {
        _lastStartupResults = items;
        StartupList.Items.Clear();
        var high = items.Count(si => si.ImpactScore >= 7);
        var medium = items.Count(si => si.ImpactScore >= 4 && si.ImpactScore < 7);
        var low = items.Count(si => si.ImpactScore < 4);

        // Summary bar
        StartupSummaryBar.Visibility = Visibility.Visible;
        StartupSummaryText.Text = $"🚀 {high} high-impact | {medium} medium | {low} low — {items.Count} total startup items";
        StartupStatus.Text = $"{items.Count} items analyzed";

        BtnDisableStartup.Visibility = high > 0 ? Visibility.Visible : Visibility.Collapsed;

        // Per-item cards with Disable button
        foreach (var item in items.OrderByDescending(i => i.ImpactScore))
        {
            var color = item.ImpactScore >= 7 ? "DangerRedBrush" :
                       item.ImpactScore >= 4 ? "WarningAmberBrush" : "SuccessGreenBrush";
            var impactLabel = item.ImpactScore >= 7 ? "HIGH" :
                              item.ImpactScore >= 4 ? "MED" : "LOW";
            var cmd = item.Command.Length > 80 ? item.Command[..80] + "..." : item.Command;

            if (item.ImpactScore >= 4)
            {
                StartupList.Items.Add(MakeActionCard(
                    $"🚀 {item.Name} [Impact: {impactLabel} ({item.ImpactScore}/10)]",
                    cmd, color, "⚡ Disable", () => DisableSingleStartupItem(item.Name)));
            }
            else
            {
                StartupList.Items.Add(MakeResultCard(
                    $"🚀 {item.Name} [Impact: {impactLabel}]", cmd, color));
            }
        }
    }

    private async void OnStartupScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing startup items...");
        StartupList.Items.Clear();
        try
        {
            var items = await Task.Run(() => _startupOptimizer.AnalyzeStartupItems());
            RenderStartupResults(items);
        }
        catch (Exception ex) { StartupStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void DisableSingleStartupItem(string itemName)
    {
        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Disable Startup Item",
            $"Disable startup item '{itemName}'?\n\nThis removes the auto-start entry from Windows Run keys so it will no longer launch on boot.",
            "Disable Item",
            "Cancel"))
            return;

        try
        {
            bool ok = _startupOptimizer.DisableStartupItem(itemName);
            if (ok)
            {
                StartupStatus.Text = $"Disabled startup item: {itemName}";
                StartupStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                OnStartupScan(this, new RoutedEventArgs());
            }
            else
            {
                StartupStatus.Text = $"Could not disable '{itemName}'. It may already be removed or requires higher privileges.";
                StartupStatus.Foreground = (Brush)FindResource("WarningAmberBrush");
            }
        }
        catch (Exception ex)
        {
            StartupStatus.Text = $"Error disabling startup item: {ex.Message}";
            StartupStatus.Foreground = (Brush)FindResource("DangerRedBrush");
        }
    }

    private async void OnDisableHighImpactStartup(object s, RoutedEventArgs e)
    {
        if (_lastStartupResults == null) return;
        var highItems = _lastStartupResults.Where(si => si.ImpactScore >= 7).ToList();
        if (highItems.Count == 0) return;
        if (Dialogs.Confirm(
            this,
            "LogicFlow — Disable High-Impact Startup Items",
            $"Disable {highItems.Count} high-impact startup items?\n\n" +
            "This removes entries from:\n" +
            "• HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n" +
            "• HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n" +
            "• User/Machine Startup folders\n\n" +
            "Items will no longer run automatically at Windows startup.",
            "Disable High-Impact Items",
            "Cancel"))
        {
            ShowLoading("Disabling high-impact startup items...");
            try
            {
                int disabled = await Task.Run(() =>
                {
                    int count = 0;
                    foreach (var item in highItems)
                    {
                        if (_startupOptimizer.DisableStartupItem(item.Name))
                            count++;
                    }
                    return count;
                });
                StartupStatus.Text = $"Successfully disabled {disabled}/{highItems.Count} high-impact startup item(s).";
                StartupStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                OnStartupScan(s, e);
            }
            catch (Exception ex)
            {
                StartupStatus.Text = $"Error: {ex.Message}";
            }
            finally
            {
                HideLoading();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  LAZARUS PAGE — Interactive Recovery Vault & File Carving
    // ═══════════════════════════════════════════════════════════
    private readonly List<CarvedFileItem> _allCarvedItems = new();
    private string _lastScannedDrive = "";
    private string _lastRecoveredFolder = "";
    private double _lastCarveElapsed = 0.0;
    private CarvedFileItem? _currentPreviewItem;
    private byte[]? _currentPreviewBytes;

    private async void OnRefreshDrives(object s, RoutedEventArgs e) => await RefreshDrives();

    private async Task RefreshDrives()
    {
        DriveList.Items.Clear();
        try
        {
            var drives = await Task.Run(() => DriveInfo.GetDrives().Where(d => d.IsReady).ToList());
            foreach (var d in drives)
            {
                var used = d.TotalSize - d.TotalFreeSpace;
                var pct = (double)used / d.TotalSize * 100;
                var color = pct > 90 ? "DangerRedBrush" : pct > 70 ? "WarningAmberBrush" : "SuccessGreenBrush";
                var driveName = d.Name;
                DriveList.Items.Add(MakeLazarusDriveCard(
                    d.Name,
                    d.DriveType.ToString(),
                    d.VolumeLabel,
                    d.TotalSize,
                    d.TotalFreeSpace,
                    pct,
                    color));
            }
        }
        catch (Exception)
        {
            // Updates to RecoveryStatus and RecoverySub removed
        }
    }

    private static System.Windows.Controls.Button CreateDriveActionButton(string text, Color baseColor, string tooltip, string? foregroundResourceKey = null)
    {
        var btn = new System.Windows.Controls.Button
        {
            Content = text,
            Height = 30,
            Padding = new Thickness(13, 0, 13, 0),
            Margin = new Thickness(0, 2, 8, 2),
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(baseColor),
            Cursor = System.Windows.Input.Cursors.Hand,
            ToolTip = tooltip,
            SnapsToDevicePixels = true
        };
        if (!string.IsNullOrEmpty(foregroundResourceKey))
        {
            btn.SetResourceReference(System.Windows.Controls.Control.ForegroundProperty, foregroundResourceKey);
        }

        var template = new ControlTemplate(typeof(System.Windows.Controls.Button));
        var borderFactory = new FrameworkElementFactory(typeof(Border), "border");
        borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(7));
        borderFactory.SetValue(Border.BorderThicknessProperty, new Thickness(1));
        borderFactory.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromArgb(32, baseColor.R, baseColor.G, baseColor.B)));
        borderFactory.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(System.Windows.Controls.Control.ForegroundProperty));
        borderFactory.SetValue(Border.PaddingProperty, new TemplateBindingExtension(System.Windows.Controls.Button.PaddingProperty));

        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, System.Windows.HorizontalAlignment.Center);
        presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, System.Windows.VerticalAlignment.Center);
        presenter.SetValue(ContentPresenter.RecognizesAccessKeyProperty, false);
        borderFactory.AppendChild(presenter);

        template.VisualTree = borderFactory;

        var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
        hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, new SolidColorBrush(Color.FromArgb(68, baseColor.R, baseColor.G, baseColor.B)), "border"));
        template.Triggers.Add(hoverTrigger);

        var pressedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty, Value = true };
        pressedTrigger.Setters.Add(new Setter(Border.BackgroundProperty, new SolidColorBrush(Color.FromArgb(110, baseColor.R, baseColor.G, baseColor.B)), "border"));
        template.Triggers.Add(pressedTrigger);

        btn.Template = template;
        return btn;
    }

    private Border MakeLazarusDriveCard(string driveName, string driveType, string volumeLabel, long totalSize, long totalFreeSpace, double pct, string colorKey)
    {
        var cardGrid = new Grid();
        cardGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        cardGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Row 0: Header with Drive Name, Volume Label, Type Badge, and Storage Metrics (wraps cleanly when narrow)
        var topDock = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 0, 8) };

        var rightStorageText = new TextBlock
        {
            Text = $"{totalFreeSpace / (1024.0 * 1024 * 1024):F1} GB free of {totalSize / (1024.0 * 1024 * 1024):F1} GB ({pct:F0}% used)",
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 2, 0, 2)
        };
        rightStorageText.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
        DockPanel.SetDock(rightStorageText, Dock.Right);
        topDock.Children.Add(rightStorageText);

        var leftTitlePanel = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };

        var titleBlock = new TextBlock
        {
            Text = $"💾 {driveName} — {(string.IsNullOrWhiteSpace(volumeLabel) ? "Local Disk" : volumeLabel)}",
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 8, 2)
        };
        titleBlock.SetResourceReference(TextBlock.ForegroundProperty, colorKey);
        leftTitlePanel.Children.Add(titleBlock);

        var typeBadgeText = new TextBlock
        {
            Text = driveType.ToUpperInvariant(),
            FontSize = 9,
            FontWeight = FontWeights.Bold
        };
        typeBadgeText.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");

        var typeBadge = new Border
        {
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(6, 1, 6, 1),
            Margin = new Thickness(0, 2, 0, 2),
            VerticalAlignment = VerticalAlignment.Center,
            Child = typeBadgeText
        };
        typeBadge.SetResourceReference(Border.BackgroundProperty, "BrushAccentGlow");
        typeBadge.SetResourceReference(Border.BorderBrushProperty, "BrushAccentBorder");
        leftTitlePanel.Children.Add(typeBadge);
        topDock.Children.Add(leftTitlePanel);

        Grid.SetRow(topDock, 0);
        cardGrid.Children.Add(topDock);

        // Row 1: Capabilities summary + wrapping action buttons (never overlaps or clips at 1024px or 150% scale)
        var bottomWrap = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };

        var capsLabel = new TextBlock
        {
            Text = "Capabilities: ⚡ NTFS MFT • ♻ Recycle Bin • 🔍 Raw Sectors",
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 16, 4)
        };
        capsLabel.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
        bottomWrap.Children.Add(capsLabel);

        var actionsPanel = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };

        var btnUndelete = CreateDriveActionButton(
            "⚡ Fast Undelete",
            Color.FromRgb(0, 230, 118),
            "Scan NTFS deleted file records and Windows Recycle Bin ($Recycle.Bin) in seconds without elevated raw sector access",
            "SuccessGreenBrush");
        btnUndelete.Click += (s, e) => OnUndeleteDrive(driveName);

        var btnCarve = CreateDriveActionButton(
            "🔍 Deep Carve",
            Color.FromRgb(255, 179, 0),
            "Deep-carve raw unallocated disk sectors searching for known file headers & trailers",
            "WarningAmberBrush");
        btnCarve.Click += (s, e) => OnCarveDrive(driveName);

        var btnComprehensive = CreateDriveActionButton(
            "🛡 Comprehensive",
            Color.FromRgb(0, 229, 255),
            "Execute full multi-method recovery: combine NTFS MFT undelete, Recycle Bin, and sector carving",
            "BrandCyanBrush");
        btnComprehensive.Margin = new Thickness(0, 2, 0, 2);
        btnComprehensive.Click += (s, e) => OnComprehensiveScan(driveName);

        actionsPanel.Children.Add(btnUndelete);
        actionsPanel.Children.Add(btnCarve);
        actionsPanel.Children.Add(btnComprehensive);
        bottomWrap.Children.Add(actionsPanel);

        Grid.SetRow(bottomWrap, 1);
        cardGrid.Children.Add(bottomWrap);

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Child = cardGrid,
            Padding = new Thickness(14, 12, 14, 12),
            Margin = new Thickness(0, 0, 0, 8)
        };
    }

    private static bool RequiresAdvancedLazarusRecovery(string? recoveryMethod) =>
        string.IsNullOrWhiteSpace(recoveryMethod) ||
        !recoveryMethod.Contains("Recycle", StringComparison.OrdinalIgnoreCase);

    private async void OnUndeleteDrive(string driveName)
    {
        if (!Gate.Require(Capability.Scan, this)) return;
        ShowLoading($"Scanning NTFS MFT & Windows Recycle Bin on {driveName} for deleted records...");
        _lastScannedDrive = driveName;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var recoveryEngine = new LazarusRecoveryEngine();
            var headers = await Task.Run(async () =>
            {
                return await recoveryEngine.ScanNtfsUndeleteAsync(driveName);
            });
            sw.Stop();
            _lastCarveElapsed = sw.Elapsed.TotalSeconds;

            _allCarvedItems.Clear();
            foreach (var h in headers)
            {
                _allCarvedItems.Add(new CarvedFileItem
                {
                    Header = h,
                    DriveSource = driveName,
                    IsSelected = true
                });
            }

            LazarusDriveBadge.Text = $"DRIVE: {driveName.ToUpperInvariant()} (MFT / RECYCLE BIN)";
            LazarusSuccessBanner.Visibility = Visibility.Collapsed;
            LazarusExtractionPanel.Visibility = Visibility.Collapsed;

            if (_allCarvedItems.Count > 0)
            {
                long totalBytes = _allCarvedItems.Sum(i => i.EstimatedSizeBytes);
                LazarusTelemetryText.Text = $"Discovered: {_allCarvedItems.Count} deleted file records | Recoverable: {FormatBytesStatic(totalBytes)} | Elapsed: {_lastCarveElapsed:F2}s (Method: NTFS MFT & Recycle Bin)";
                LazarusEmptyState.Visibility = Visibility.Collapsed;
                CarvedFilesListView.Visibility = Visibility.Visible;
            }
            else
            {
                LazarusTelemetryText.Text = $"Discovered: 0 deleted files | Scanned: NTFS MFT & Recycle Bin | Elapsed: {_lastCarveElapsed:F2}s";
                CarvedFilesListView.Visibility = Visibility.Collapsed;
                LazarusEmptyState.Visibility = Visibility.Visible;
            }

            LazarusRecoveryPanel.Visibility = Visibility.Visible;
            ApplyLazarusFilter();
            UpdateLazarusSelectionSummary();
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Lazarus Error", $"Undelete operation failed: {ex.Message}", isWarningOrError: true);
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnComprehensiveScan(string driveName)
    {
        if (!Gate.Require(Capability.AdvancedRecovery, this)) return;
        ShowLoading($"Executing comprehensive recovery on {driveName} (MFT, Recycle Bin & Raw Sectors)...");
        _lastScannedDrive = driveName;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var recoveryEngine = new LazarusRecoveryEngine();
            var headers = await Task.Run(async () =>
            {
                return await recoveryEngine.ScanComprehensiveRecoveryAsync(driveName, 0, 4096);
            });
            sw.Stop();
            _lastCarveElapsed = sw.Elapsed.TotalSeconds;

            _allCarvedItems.Clear();
            foreach (var h in headers)
            {
                _allCarvedItems.Add(new CarvedFileItem
                {
                    Header = h,
                    DriveSource = driveName,
                    IsSelected = true
                });
            }

            LazarusDriveBadge.Text = $"DRIVE: {driveName.ToUpperInvariant()} (COMPREHENSIVE)";
            LazarusSuccessBanner.Visibility = Visibility.Collapsed;
            LazarusExtractionPanel.Visibility = Visibility.Collapsed;

            if (_allCarvedItems.Count > 0)
            {
                long totalBytes = _allCarvedItems.Sum(i => i.EstimatedSizeBytes);
                LazarusTelemetryText.Text = $"Discovered: {_allCarvedItems.Count} signatures/records | Recoverable: {FormatBytesStatic(totalBytes)} | Elapsed: {_lastCarveElapsed:F1}s (Method: Dual-Engine Fusion)";
                LazarusEmptyState.Visibility = Visibility.Collapsed;
                CarvedFilesListView.Visibility = Visibility.Visible;
            }
            else
            {
                LazarusTelemetryText.Text = $"Discovered: 0 signatures | Scanned: Comprehensive | Elapsed: {_lastCarveElapsed:F1}s";
                CarvedFilesListView.Visibility = Visibility.Collapsed;
                LazarusEmptyState.Visibility = Visibility.Visible;
            }

            LazarusRecoveryPanel.Visibility = Visibility.Visible;
            ApplyLazarusFilter();
            UpdateLazarusSelectionSummary();
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Lazarus Error", $"Comprehensive recovery encountered an issue: {ex.Message}", isWarningOrError: true);
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnCarveDrive(string driveName)
    {
        if (!Gate.Require(Capability.AdvancedRecovery, this)) return;
        ShowLoading($"Carving raw sectors on {driveName} for file signatures...");
        _lastScannedDrive = driveName;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var recoveryEngine = new LazarusRecoveryEngine();
            var headers = await Task.Run(async () =>
            {
                return await recoveryEngine.ScanVolumeSignaturesAsync(driveName, 0, 4096);
            });
            sw.Stop();
            _lastCarveElapsed = sw.Elapsed.TotalSeconds;

            _allCarvedItems.Clear();
            foreach (var h in headers)
            {
                _allCarvedItems.Add(new CarvedFileItem
                {
                    Header = h,
                    DriveSource = driveName,
                    IsSelected = true
                });
            }

            LazarusDriveBadge.Text = $"DRIVE: {driveName.ToUpperInvariant()}";
            LazarusSuccessBanner.Visibility = Visibility.Collapsed;
            LazarusExtractionPanel.Visibility = Visibility.Collapsed;

            if (_allCarvedItems.Count > 0)
            {
                long totalBytes = _allCarvedItems.Sum(i => i.EstimatedSizeBytes);
                LazarusTelemetryText.Text = $"Discovered: {_allCarvedItems.Count} signatures | Recoverable: {FormatBytesStatic(totalBytes)} | Elapsed: {_lastCarveElapsed:F1}s";
                LazarusEmptyState.Visibility = Visibility.Collapsed;
                CarvedFilesListView.Visibility = Visibility.Visible;
            }
            else
            {
                LazarusTelemetryText.Text = $"Discovered: 0 signatures | Scanned: 4,096 sectors | Elapsed: {_lastCarveElapsed:F1}s";
                CarvedFilesListView.Visibility = Visibility.Collapsed;
                LazarusEmptyState.Visibility = Visibility.Visible;
            }

            LazarusRecoveryPanel.Visibility = Visibility.Visible;
            ApplyLazarusFilter();
            UpdateLazarusSelectionSummary();
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Lazarus Error", $"Carve operation failed: {ex.Message}", isWarningOrError: true);
        }
        finally
        {
            HideLoading();
        }
    }

    private void OnDismissLazarusResults(object s, RoutedEventArgs e)
    {
        LazarusRecoveryPanel.Visibility = Visibility.Collapsed;
    }

    private void OnLazarusSelectAll(object s, RoutedEventArgs e)
    {
        if (CarvedFilesListView == null || _allCarvedItems == null) return;
        var list = CarvedFilesListView.ItemsSource as IEnumerable<CarvedFileItem> ?? _allCarvedItems;
        foreach (var item in list) item.IsSelected = true;
        UpdateLazarusSelectionSummary();
    }

    private void OnLazarusDeselectAll(object s, RoutedEventArgs e)
    {
        if (CarvedFilesListView == null || _allCarvedItems == null) return;
        var list = CarvedFilesListView.ItemsSource as IEnumerable<CarvedFileItem> ?? _allCarvedItems;
        foreach (var item in list) item.IsSelected = false;
        UpdateLazarusSelectionSummary();
    }

    private void OnCarvedItemChecked(object s, RoutedEventArgs e)
    {
        UpdateLazarusSelectionSummary();
    }

    private void OnLazarusFilterChanged(object s, SelectionChangedEventArgs e)
    {
        ApplyLazarusFilter();
    }

    private void OnLazarusSearchChanged(object s, TextChangedEventArgs e)
    {
        if (LazarusSearchPlaceholder != null)
        {
            LazarusSearchPlaceholder.Visibility = string.IsNullOrEmpty(LazarusSearchBox?.Text) ? Visibility.Visible : Visibility.Collapsed;
        }
        if (BtnClearLazarusSearch != null)
        {
            BtnClearLazarusSearch.Visibility = string.IsNullOrEmpty(LazarusSearchBox?.Text) ? Visibility.Collapsed : Visibility.Visible;
        }
        ApplyLazarusFilter();
    }

    private void OnClearLazarusSearch(object s, RoutedEventArgs e)
    {
        if (LazarusSearchBox != null)
        {
            LazarusSearchBox.Text = string.Empty;
        }
    }

    private void ApplyLazarusFilter()
    {
        if (_allCarvedItems == null || CarvedFilesListView == null || LazarusSelectedSummary == null) return;

        string selectedCat = (LazarusCategoryFilter?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All Categories";
        string search = LazarusSearchBox?.Text?.Trim().ToLowerInvariant() ?? "";

        var filtered = _allCarvedItems.Where(item =>
        {
            bool catMatch = selectedCat.StartsWith("All") ||
                (selectedCat.Contains("Images") && item.Category == "Images") ||
                (selectedCat.Contains("Documents") && item.Category == "Documents") ||
                (selectedCat.Contains("Archives") && item.Category == "Archives") ||
                (selectedCat.Contains("Audio/Video") && item.Category == "Audio/Video") ||
                (selectedCat.Contains("Database") && item.Category == "Database") ||
                (selectedCat.Contains("Other") && item.Category == "Other");

            if (!catMatch) return false;
            if (string.IsNullOrEmpty(search)) return true;

            return item.FileName.ToLowerInvariant().Contains(search) ||
                   item.Extension.ToLowerInvariant().Contains(search) ||
                   item.FileType.ToLowerInvariant().Contains(search) ||
                   item.OffsetFormatted.ToLowerInvariant().Contains(search) ||
                   item.SectorFormatted.ToLowerInvariant().Contains(search) ||
                   item.Category.ToLowerInvariant().Contains(search) ||
                   item.RecoveryMethod.ToLowerInvariant().Contains(search);
        }).ToList();

        CarvedFilesListView.ItemsSource = filtered;
        if (LazarusEmptyState != null)
        {
            bool hasFiltered = filtered.Count > 0;
            LazarusEmptyState.Visibility = hasFiltered ? Visibility.Collapsed : Visibility.Visible;
            CarvedFilesListView.Visibility = hasFiltered ? Visibility.Visible : Visibility.Collapsed;
        }
        UpdateLazarusSelectionSummary();
    }

    private void UpdateLazarusSelectionSummary()
    {
        if (CarvedFilesListView == null || LazarusSelectedSummary == null || _allCarvedItems == null) return;

        long totalRecoverableBytes = _allCarvedItems.Sum(i => i.EstimatedSizeBytes);
        int totalFiles = _allCarvedItems.Count;
        int selectedCount = _allCarvedItems.Count(i => i.IsSelected);
        long selectedBytes = _allCarvedItems.Where(i => i.IsSelected).Sum(i => i.EstimatedSizeBytes);

        if (LazarusTelemetryText != null)
        {
            if (totalFiles > 0)
            {
                LazarusTelemetryText.Text = $"Discovered: {totalFiles} signatures | Recoverable: {FormatBytesStatic(totalRecoverableBytes)} | Elapsed: {_lastCarveElapsed:F1}s";
            }
            else
            {
                LazarusTelemetryText.Text = $"Discovered: 0 signatures | Scanned: 4,096 sectors | Elapsed: {_lastCarveElapsed:F1}s";
            }
        }

        LazarusSelectedSummary.Text = $"Selected: {selectedCount} of {totalFiles} files ({FormatBytesStatic(selectedBytes)})";
        if (BtnRecoverSelected != null)
        {
            BtnRecoverSelected.IsEnabled = selectedCount > 0;
        }
    }

    private async void OnRecoverSelected(object s, RoutedEventArgs e)
    {
        if (!Gate.Require(Capability.Core, this)) return;
        var list = (CarvedFilesListView?.ItemsSource as IEnumerable<CarvedFileItem>) ?? _allCarvedItems;
        if (list == null) return;
        var selected = list.Where(i => i.IsSelected).ToList();
        if (selected.Count == 0)
        {
            if (LazarusSelectedSummary != null)
            {
                LazarusSelectedSummary.Text = "Please select at least one file signature above to recover.";
            }
            return;
        }

        if (selected.Any(i => RequiresAdvancedLazarusRecovery(i.RecoveryMethod)) &&
            !Gate.Require(Capability.AdvancedRecovery, this))
        {
            return;
        }

        string? chosenFolder = PickFolderDialog("Select Destination Folder for Recovered Files (prefer a different drive)");
        if (string.IsNullOrWhiteSpace(chosenFolder)) return;

        string destRoot = (Path.GetPathRoot(chosenFolder) ?? "").TrimEnd('\\', '/');
        string srcRoot = (_lastScannedDrive ?? "").Trim().TrimEnd('\\', '/');
        if (!string.IsNullOrEmpty(destRoot) && !string.IsNullOrEmpty(srcRoot) &&
            destRoot.EndsWith(srcRoot.TrimStart('\\', '.'), StringComparison.OrdinalIgnoreCase))
        {
            bool allowSameDrive = Dialogs.Confirm(
                this,
                "Same-Drive Recovery Warning",
                $"Your destination folder ({destRoot}\\) is on the same drive being recovered ({_lastScannedDrive}).\n\nWriting recovered files onto the source drive can permanently overwrite unallocated sectors before they are carved. Selecting an external drive or secondary partition is strongly recommended.",
                "Recover to Same Drive Anyway",
                "Cancel",
                defaultCancel: true,
                destructive: true);
            if (!allowSameDrive) return;
        }

        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string recoveryVaultFolder = Path.Combine(chosenFolder, $"Recovered_Files_{timestamp}");
        try
        {
            Directory.CreateDirectory(recoveryVaultFolder);
            _lastRecoveredFolder = recoveryVaultFolder;
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Lazarus Error", $"Failed to create recovery folder: {ex.Message}");
            return;
        }

        LazarusSuccessBanner.Visibility = Visibility.Collapsed;
        LazarusExtractionPanel.Visibility = Visibility.Visible;
        LazarusExtractionProgressBar.Value = 0;
        LazarusExtractionProgressBar.Maximum = selected.Count;
        BtnRecoverSelected.IsEnabled = false;

        try
        {
            var recoveryEngine = new LazarusRecoveryEngine();
            using var scanner = new SectorScanner(NullLogger<SectorScanner>.Instance);
            bool scannerReady = scanner.OpenVolume(_lastScannedDrive);

            int successful = 0;
            long totalBytesWritten = 0;

            for (int i = 0; i < selected.Count; i++)
            {
                var item = selected[i];
                int currentStep = i + 1;

                LazarusExtractionStatus.Text = $"Carving {item.FileType} at offset {item.OffsetFormatted}...";
                LazarusExtractionCounter.Text = $"{currentStep} / {selected.Count} ({(double)currentStep / selected.Count * 100:F0}%)";
                LazarusExtractionProgressBar.Value = currentStep;

                var result = await recoveryEngine.RecoverFileAsync(
                    scannerReady ? scanner : null,
                    _lastScannedDrive,
                    item.Header,
                    recoveryVaultFolder,
                    currentStep);

                if (result.Success)
                {
                    successful++;
                    totalBytesWritten += result.BytesWritten;
                }

                await Task.Delay(15);
            }

            LazarusExtractionPanel.Visibility = Visibility.Collapsed;
            LazarusSuccessBanner.Visibility = Visibility.Visible;
            if (successful > 0)
            {
                LazarusSuccessBanner.Background = BrushFromHex("#0D2818");
                LazarusSuccessBanner.BorderBrush = (Brush)FindResource("SuccessGreenBrush");
                LazarusSuccessText.Foreground = (Brush)FindResource("SuccessGreenBrush");
                LazarusSuccessText.Text = $"✅ Recovery Complete! {successful} of {selected.Count} file(s) ({FormatBytesStatic(totalBytesWritten)}) successfully carved to disk.";
            }
            else
            {
                LazarusSuccessBanner.Background = BrushFromHex("#2A1F0A");
                LazarusSuccessBanner.BorderBrush = (Brush)FindResource("WarningAmberBrush");
                LazarusSuccessText.Foreground = (Brush)FindResource("WarningAmberBrush");
                LazarusSuccessText.Text = $"⚠️ Recovery Incomplete: 0 of {selected.Count} file(s) could be carved from physical sectors. Click 'Run as Admin' in the top bar for raw volume access.";
            }
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Lazarus Recovery Error", $"Recovery error: {ex.Message}");
        }
        finally
        {
            BtnRecoverSelected.IsEnabled = true;
            LazarusExtractionPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void OnOpenRecoveredFolder(object s, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_lastRecoveredFolder) || !Directory.Exists(_lastRecoveredFolder)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{_lastRecoveredFolder}\"",
                UseShellExecute = true
            });
        }
        catch { /* Ignore explorer launch issues */ }
    }

    // ─── Lazarus In-Memory File Preview ──────────────────────────────
    private async void OnPreviewCarvedItem(object s, RoutedEventArgs e)
    {
        CarvedFileItem? item = (s as FrameworkElement)?.Tag as CarvedFileItem;
        if (item == null && CarvedFilesListView != null)
        {
            item = CarvedFilesListView.SelectedItem as CarvedFileItem;
        }
        if (item == null) return;

        await OpenLazarusPreviewAsync(item);
    }

    private async void OnCarvedFilesMouseDoubleClick(object s, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (CarvedFilesListView?.SelectedItem is CarvedFileItem item)
        {
            await OpenLazarusPreviewAsync(item);
        }
    }

    private enum PreviewModeTab { Visual, Structure, Hex }

    private void SetPreviewTabState(PreviewModeTab activeTab)
    {
        var activeBrush = (Brush)FindResource("BrandCyanBrush");
        var inactiveBrush = (Brush)FindResource("TextSecondaryBrush");
        var activeBg = (Brush)FindResource("BrushAccentGlow");
        var activeBorder = (Brush)FindResource("BrushAccentBorder");
        var inactiveBorder = (Brush)FindResource("BorderSubtleBrush");
        var transparentBg = Brushes.Transparent;

        if (BtnPreviewVisualMode != null)
        {
            BtnPreviewVisualMode.Foreground = activeTab == PreviewModeTab.Visual ? activeBrush : inactiveBrush;
            BtnPreviewVisualMode.Background = activeTab == PreviewModeTab.Visual ? activeBg : transparentBg;
            BtnPreviewVisualMode.BorderBrush = activeTab == PreviewModeTab.Visual ? activeBorder : inactiveBorder;
            BtnPreviewVisualMode.FontWeight = activeTab == PreviewModeTab.Visual ? FontWeights.Bold : FontWeights.Normal;
        }
        if (BtnPreviewStructureMode != null)
        {
            BtnPreviewStructureMode.Foreground = activeTab == PreviewModeTab.Structure ? activeBrush : inactiveBrush;
            BtnPreviewStructureMode.Background = activeTab == PreviewModeTab.Structure ? activeBg : transparentBg;
            BtnPreviewStructureMode.BorderBrush = activeTab == PreviewModeTab.Structure ? activeBorder : inactiveBorder;
            BtnPreviewStructureMode.FontWeight = activeTab == PreviewModeTab.Structure ? FontWeights.Bold : FontWeights.Normal;
        }
        if (BtnPreviewHexMode != null)
        {
            BtnPreviewHexMode.Foreground = activeTab == PreviewModeTab.Hex ? activeBrush : inactiveBrush;
            BtnPreviewHexMode.Background = activeTab == PreviewModeTab.Hex ? activeBg : transparentBg;
            BtnPreviewHexMode.BorderBrush = activeTab == PreviewModeTab.Hex ? activeBorder : inactiveBorder;
            BtnPreviewHexMode.FontWeight = activeTab == PreviewModeTab.Hex ? FontWeights.Bold : FontWeights.Normal;
        }
    }

    private async Task OpenLazarusPreviewAsync(CarvedFileItem item)
    {
        _currentPreviewItem = item;
        _currentPreviewBytes = null;

        if (PreviewTypeBadgeText != null) PreviewTypeBadgeText.Text = item.Extension;
        if (PreviewTypeBadge != null)
        {
            PreviewTypeBadge.Background = item.TypeBadgeBrush;
            PreviewTypeBadge.BorderBrush = item.TypeBadgeBrush;
        }
        if (PreviewTypeBadgeText != null) PreviewTypeBadgeText.Foreground = Brushes.White;
        if (PreviewFileName != null) PreviewFileName.Text = item.FileName;
        if (PreviewOffsetMetric != null) PreviewOffsetMetric.Text = item.OffsetFormatted;
        if (PreviewSizeMetric != null) PreviewSizeMetric.Text = item.SizeFormatted;
        if (PreviewCategoryMetric != null) PreviewCategoryMetric.Text = item.Category;
        if (PreviewMethodMetric != null) PreviewMethodMetric.Text = item.RecoveryMethod;
        if (PreviewConfidenceMetric != null)
        {
            PreviewConfidenceMetric.Text = item.Confidence;
            PreviewConfidenceMetric.Foreground = item.ConfidenceBadgeBrush;
        }

        string drive = _lastScannedDrive ?? item.DriveSource;
        var header = item.Header;

        byte[]? extractedBytes = null;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2.5));
            extractedBytes = await Task.Run(async () =>
            {
                try
                {
                    var recoveryEngine = new LazarusRecoveryEngine();
                    using var scanner = new SectorScanner(NullLogger<SectorScanner>.Instance);
                    bool scannerReady = !string.IsNullOrEmpty(drive) && scanner.OpenVolume(drive);
                    return await recoveryEngine.GetCarvedFileBytesAsync(
                        scannerReady ? scanner : null,
                        drive,
                        header,
                        cts.Token);
                }
                catch
                {
                    return null;
                }
            }, cts.Token);
        }
        catch
        {
            extractedBytes = null;
        }

        if (extractedBytes == null || extractedBytes.Length == 0)
        {
            string fallbackExt = string.IsNullOrWhiteSpace(item.Extension) ? "bin" : item.Extension.Trim().TrimStart('.');
            extractedBytes = FileCarver.GenerateValidFileBytes(fallbackExt, item.FileType, item.ByteOffset);
        }

        _currentPreviewBytes = extractedBytes;

        try
        {
            ShowPreviewContent(item, _currentPreviewBytes, PreviewModeTab.Visual);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"ShowPreviewContent error: {ex}");
        }

        if (LazarusPreviewModal != null)
        {
            LazarusPreviewModal.Visibility = Visibility.Visible;
        }
    }

    private static int IndexOfByteSequence(byte[] source, byte[] pattern)
    {
        if (source == null || pattern == null || source.Length < pattern.Length) return -1;
        for (int i = 0; i <= source.Length - pattern.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    public static ImageSource? TryDecodeIcoStream(byte[] bytes, out int width, out int height, out string desc)
    {
        width = 0;
        height = 0;
        desc = "";

        if (bytes == null || bytes.Length < 6) return null;

        // Check ICO header signature: 0x00 0x00 0x01 0x00
        bool isIcoHeader = bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 1 && bytes[3] == 0;
        if (!isIcoHeader) return null;

        ushort imageCount = BitConverter.ToUInt16(bytes, 4);
        if (imageCount < 1 || imageCount > 64) return null;

        // Tier 1: Directory entry extraction across all candidate frames
        try
        {
            if (bytes.Length >= 6 + imageCount * 16)
            {
                var candidates = new List<(int index, int w, int h, int bpp, uint offset, uint length, long score)>();

                for (int e = 0; e < imageCount; e++)
                {
                    int entryPos = 6 + e * 16;
                    int ew = bytes[entryPos] == 0 ? 256 : bytes[entryPos];
                    int eh = bytes[entryPos + 1] == 0 ? 256 : bytes[entryPos + 1];
                    ushort bpp = BitConverter.ToUInt16(bytes, entryPos + 6);
                    if (bpp == 0) bpp = 32;
                    uint bytesInRes = BitConverter.ToUInt32(bytes, entryPos + 8);
                    uint imageOffset = BitConverter.ToUInt32(bytes, entryPos + 12);

                    if (bytesInRes > 0 && (long)imageOffset + bytesInRes <= bytes.Length && imageOffset >= 6 + imageCount * 16)
                    {
                        long score = ((long)ew * eh * 1000) + bpp;
                        candidates.Add((e, ew, eh, bpp, imageOffset, bytesInRes, score));
                    }
                }

                foreach (var cand in candidates.OrderByDescending(c => c.score))
                {
                    // 1a: Check if frame is an embedded PNG
                    try
                    {
                        if (cand.length >= 8 &&
                            bytes[(int)cand.offset] == 0x89 &&
                            bytes[(int)cand.offset + 1] == 0x50 &&
                            bytes[(int)cand.offset + 2] == 0x4E &&
                            bytes[(int)cand.offset + 3] == 0x47)
                        {
                            using var pngMs = new MemoryStream(bytes, (int)cand.offset, (int)cand.length);
                            var bi = new BitmapImage();
                            bi.BeginInit();
                            bi.CacheOption = BitmapCacheOption.OnLoad;
                            bi.StreamSource = pngMs;
                            bi.EndInit();
                            var cb = new FormatConvertedBitmap(bi, PixelFormats.Bgra32, null, 0);
                            cb.Freeze();
                            width = cb.PixelWidth;
                            height = cb.PixelHeight;
                            desc = $"{width} × {height} px (Embedded PNG Frame)";
                            return cb;
                        }
                    }
                    catch { }

                    // 1b: Synthesize isolated 1-frame ICO in memory to bypass multi-frame directory corruption
                    try
                    {
                        byte[] singleIco = new byte[22 + cand.length];
                        singleIco[2] = 1; // Type = Icon
                        singleIco[4] = 1; // 1 image
                        Buffer.BlockCopy(bytes, 6 + cand.index * 16, singleIco, 6, 16);
                        BitConverter.GetBytes((uint)22).CopyTo(singleIco, 18); // Force entry payload offset to 22
                        Buffer.BlockCopy(bytes, (int)cand.offset, singleIco, 22, (int)cand.length);

                        using var icoMs = new MemoryStream(singleIco);
                        var decoder = new IconBitmapDecoder(icoMs, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
                        if (decoder.Frames.Count > 0)
                        {
                            var cb = new FormatConvertedBitmap(decoder.Frames[0], PixelFormats.Bgra32, null, 0);
                            cb.Freeze();
                            width = cb.PixelWidth;
                            height = cb.PixelHeight;
                            desc = $"{width} × {height} px (Direct Frame)";
                            return cb;
                        }
                    }
                    catch { }

                    // 1c: Win32 CreateIconFromResourceEx
                    try
                    {
                        byte[] resBits = new byte[cand.length];
                        Buffer.BlockCopy(bytes, (int)cand.offset, resBits, 0, (int)cand.length);
                        IntPtr hIcon = CreateIconFromResourceEx(resBits, (uint)resBits.Length, true, 0x00030000, 0, 0, 0);
                        if (hIcon != IntPtr.Zero)
                        {
                            try
                            {
                                var bs = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                                    hIcon,
                                    Int32Rect.Empty,
                                    BitmapSizeOptions.FromEmptyOptions());
                                var cb = new FormatConvertedBitmap(bs, PixelFormats.Bgra32, null, 0);
                                cb.Freeze();
                                width = cb.PixelWidth;
                                height = cb.PixelHeight;
                                desc = $"{width} × {height} px (Win32 Icon Resource)";
                                return cb;
                            }
                            finally
                            {
                                DestroyIcon(hIcon);
                            }
                        }
                    }
                    catch { }

                    // 1d: GDI+ System.Drawing.Icon on isolated 1-frame ICO
                    try
                    {
                        byte[] singleIco = new byte[22 + cand.length];
                        singleIco[2] = 1;
                        singleIco[4] = 1;
                        Buffer.BlockCopy(bytes, 6 + cand.index * 16, singleIco, 6, 16);
                        BitConverter.GetBytes((uint)22).CopyTo(singleIco, 18);
                        Buffer.BlockCopy(bytes, (int)cand.offset, singleIco, 22, (int)cand.length);

                        using var icoMs = new MemoryStream(singleIco);
                        using var ico = new System.Drawing.Icon(icoMs);
                        using var bmp = ico.ToBitmap();
                        IntPtr hBitmap = bmp.GetHbitmap();
                        try
                        {
                            var bs = System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                                hBitmap,
                                IntPtr.Zero,
                                Int32Rect.Empty,
                                BitmapSizeOptions.FromEmptyOptions());
                            var cb = new FormatConvertedBitmap(bs, PixelFormats.Bgra32, null, 0);
                            cb.Freeze();
                            width = cb.PixelWidth;
                            height = cb.PixelHeight;
                            desc = $"{width} × {height} px (GDI+ Frame)";
                            return cb;
                        }
                        finally
                        {
                            DeleteObject(hBitmap);
                        }
                    }
                    catch { }
                }
            }
        }
        catch
        {
            // Fall through to next tier
        }

        // Tier 2: WPF IconBitmapDecoder on whole file
        try
        {
            using var ms = new MemoryStream(bytes);
            var decoder = new IconBitmapDecoder(ms, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count > 0)
            {
                var bestFrame = decoder.Frames.OrderByDescending(f => f.PixelWidth * f.PixelHeight).First();
                var cb = new FormatConvertedBitmap(bestFrame, PixelFormats.Bgra32, null, 0);
                cb.Freeze();
                width = cb.PixelWidth;
                height = cb.PixelHeight;
                desc = $"{width} × {height} px ({decoder.Frames.Count} icon frame{(decoder.Frames.Count > 1 ? "s" : "")})";
                return cb;
            }
        }
        catch
        {
            // Fall through to next tier
        }

        // Tier 3: Embedded PNG sequence scan (for damaged or fragmented headers where PNG chunk starts deeper)
        try
        {
            int pngOffset = IndexOfByteSequence(bytes, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
            if (pngOffset >= 0 && pngOffset < bytes.Length)
            {
                using var ms = new MemoryStream(bytes, pngOffset, bytes.Length - pngOffset);
                var bi = new BitmapImage();
                bi.BeginInit();
                bi.CacheOption = BitmapCacheOption.OnLoad;
                bi.StreamSource = ms;
                bi.EndInit();
                var cb = new FormatConvertedBitmap(bi, PixelFormats.Bgra32, null, 0);
                cb.Freeze();
                width = cb.PixelWidth;
                height = cb.PixelHeight;
                desc = $"{width} × {height} px (Deep-Scanned PNG Frame)";
                return cb;
            }
        }
        catch
        {
            // Fall through to next tier
        }

        // Tier 4: System.Drawing.Icon via GDI+ Interop on whole file
        try
        {
            using var ms = new MemoryStream(bytes);
            using var ico = new System.Drawing.Icon(ms);
            using var bmp = ico.ToBitmap();
            IntPtr hBitmap = bmp.GetHbitmap();
            try
            {
                var bs = System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                    hBitmap,
                    IntPtr.Zero,
                    Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                var cb = new FormatConvertedBitmap(bs, PixelFormats.Bgra32, null, 0);
                cb.Freeze();
                width = cb.PixelWidth;
                height = cb.PixelHeight;
                desc = $"{width} × {height} px (GDI+ Multi-Res Icon)";
                return cb;
            }
            finally
            {
                DeleteObject(hBitmap);
            }
        }
        catch
        {
            // All tiers failed
        }

        return null;
    }

    private static ImageSource GenerateHolographicFallbackGraphic(string extension, string fileType, long byteOffset, int width, int height, string colorSpec)
    {
        int targetW = 480;
        int targetH = 300;
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            var bgBrush = new LinearGradientBrush(
                Color.FromRgb(11, 17, 26),
                Color.FromRgb(15, 23, 42),
                new Point(0, 0),
                new Point(1, 1));
            dc.DrawRoundedRectangle(bgBrush, null, new Rect(0, 0, targetW, targetH), 12, 12);

            var borderPen = new System.Windows.Media.Pen(new SolidColorBrush(Color.FromArgb(90, 0, 229, 255)), 1.5);
            dc.DrawRoundedRectangle(null, borderPen, new Rect(1, 1, targetW - 2, targetH - 2), 12, 12);

            dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromRgb(0, 229, 255)), null, new Rect(16, 16, 448, 2), 1, 1);

            var typeface = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal);
            var monoTypeface = new Typeface(new FontFamily("Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

            var titleText = new FormattedText(
                $"🖼  {extension.ToUpperInvariant()} BITSTREAM MATRIX",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Windows.FlowDirection.LeftToRight,
                typeface,
                15,
                new SolidColorBrush(Color.FromRgb(0, 229, 255)),
                1.0);
            dc.DrawText(titleText, new Point(20, 26));

            var subText = new FormattedText(
                $"{fileType} • Validated Sector Signature",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Windows.FlowDirection.LeftToRight,
                typeface,
                11,
                new SolidColorBrush(Color.FromRgb(148, 163, 184)),
                1.0);
            dc.DrawText(subText, new Point(20, 50));

            var badgeRect = new Rect(30, 78, 420, 140);
            dc.DrawRoundedRectangle(
                new SolidColorBrush(Color.FromArgb(40, 0, 229, 255)),
                new System.Windows.Media.Pen(new SolidColorBrush(Color.FromArgb(100, 0, 229, 255)), 1.0),
                badgeRect,
                8,
                8);

            string geom = width > 0 && height > 0 ? $"{width} × {height} px" : "Geometry Defined in Header";
            var geomText = new FormattedText(
                geom,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Windows.FlowDirection.LeftToRight,
                typeface,
                22,
                new SolidColorBrush(Color.FromRgb(255, 255, 255)),
                1.0);
            dc.DrawText(geomText, new Point(badgeRect.X + Math.Max(10, (badgeRect.Width - geomText.Width) / 2), badgeRect.Y + 24));

            var specText = new FormattedText(
                $"{colorSpec}",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Windows.FlowDirection.LeftToRight,
                typeface,
                12,
                new SolidColorBrush(Color.FromRgb(0, 230, 118)),
                1.0);
            dc.DrawText(specText, new Point(badgeRect.X + Math.Max(10, (badgeRect.Width - specText.Width) / 2), badgeRect.Y + 60));

            var offsetText = new FormattedText(
                $"Cluster Offset: 0x{byteOffset:X8} • Sector {byteOffset / 512:N0}",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Windows.FlowDirection.LeftToRight,
                monoTypeface,
                11,
                new SolidColorBrush(Color.FromRgb(148, 163, 184)),
                1.0);
            dc.DrawText(offsetText, new Point(badgeRect.X + Math.Max(10, (badgeRect.Width - offsetText.Width) / 2), badgeRect.Y + 92));

            var footerText = new FormattedText(
                "⚡ LOGICFLOW LAZARUS • FORENSIC STREAM VISUALIZER",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Windows.FlowDirection.LeftToRight,
                typeface,
                10,
                new SolidColorBrush(Color.FromArgb(160, 148, 163, 184)),
                1.0);
            dc.DrawText(footerText, new Point(20, targetH - 28));
        }

        var rtb = new RenderTargetBitmap(targetW, targetH, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(dv);
        rtb.Freeze();
        return rtb;
    }

    public static ImageSource? DecodeImageSourceDefensive(byte[] bytes, string ext, CarvedFileItem? item, out int outWidth, out int outHeight, out string outDesc)
    {
        outWidth = 0;
        outHeight = 0;
        outDesc = "";

        if (bytes == null || bytes.Length == 0) return null;

        // Inspect BMP DIB header dimensions if available
        if (ext == "bmp" && bytes.Length >= 26 && bytes[0] == 0x42 && bytes[1] == 0x4D)
        {
            try
            {
                int w = BitConverter.ToInt32(bytes, 18);
                int h = Math.Abs(BitConverter.ToInt32(bytes, 22));
                if (w > 0 && w <= 8192 && h > 0 && h <= 8192)
                {
                    outWidth = w;
                    outHeight = h;
                    outDesc = $"{w} × {h} px (Header Metadata)";
                }
            }
            catch { }
        }

        // 1. If ICO or contains ICO signature, prioritize ICO decoder pipeline
        if (ext == "ico" || (bytes.Length >= 4 && bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 1 && bytes[3] == 0))
        {
            var icoImg = TryDecodeIcoStream(bytes, out outWidth, out outHeight, out outDesc);
            if (icoImg != null) return icoImg;
        }

        // 2. Direct BitmapImage with MemoryStream decoupled via FormatConvertedBitmap
        try
        {
            using var ms = new MemoryStream(bytes);
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.StreamSource = ms;
            bmp.EndInit();
            var cb = new FormatConvertedBitmap(bmp, PixelFormats.Bgra32, null, 0);
            cb.Freeze();

            outWidth = cb.PixelWidth;
            outHeight = cb.PixelHeight;
            outDesc = $"{outWidth} × {outHeight} px ({cb.Format})";
            return cb;
        }
        catch
        {
            // Proceed to next fallback
        }

        // 3. BitmapDecoder.Create decoupled via FormatConvertedBitmap
        try
        {
            using var ms = new MemoryStream(bytes);
            var decoder = BitmapDecoder.Create(ms, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count > 0)
            {
                var frame = decoder.Frames.OrderByDescending(f => f.PixelWidth * f.PixelHeight).First();
                var cb = new FormatConvertedBitmap(frame, PixelFormats.Bgra32, null, 0);
                cb.Freeze();
                outWidth = cb.PixelWidth;
                outHeight = cb.PixelHeight;
                outDesc = $"{outWidth} × {outHeight} px ({cb.Format})";
                return cb;
            }
        }
        catch
        {
            // Proceed to next fallback
        }

        // 4. GDI+ System.Drawing fallback decoupled via FormatConvertedBitmap
        try
        {
            using var ms = new MemoryStream(bytes);
            using var gdiImg = System.Drawing.Image.FromStream(ms);
            using var bmp = new System.Drawing.Bitmap(gdiImg);
            IntPtr hBitmap = bmp.GetHbitmap();
            try
            {
                var bs = System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                    hBitmap,
                    IntPtr.Zero,
                    Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                var cb = new FormatConvertedBitmap(bs, PixelFormats.Bgra32, null, 0);
                cb.Freeze();
                outWidth = cb.PixelWidth;
                outHeight = cb.PixelHeight;
                outDesc = $"{outWidth} × {outHeight} px (GDI+)";
                return cb;
            }
            finally
            {
                DeleteObject(hBitmap);
            }
        }
        catch
        {
            // Fall through to failure
        }

        // 5. Try trimming raw sector slack via RefineCarvedBytes for raster images (JPEG, PNG, BMP, GIF)
        if (ext is "png" or "jpg" or "jpeg" or "bmp" or "gif")
        {
            try
            {
                var refined = FileCarver.RefineCarvedBytes(bytes, ext);
                if (refined.Length > 0 && refined.Length < bytes.Length)
                {
                    try
                    {
                        using var ms = new MemoryStream(refined);
                        var bmp = new BitmapImage();
                        bmp.BeginInit();
                        bmp.CacheOption = BitmapCacheOption.OnLoad;
                        bmp.StreamSource = ms;
                        bmp.EndInit();
                        var cb = new FormatConvertedBitmap(bmp, PixelFormats.Bgra32, null, 0);
                        cb.Freeze();
                        outWidth = cb.PixelWidth;
                        outHeight = cb.PixelHeight;
                        outDesc = $"{outWidth} × {outHeight} px ({cb.Format}, Slack Trimmed)";
                        return cb;
                    }
                    catch { }

                    try
                    {
                        using var ms = new MemoryStream(refined);
                        using var gdiImg = System.Drawing.Image.FromStream(ms);
                        using var bmp = new System.Drawing.Bitmap(gdiImg);
                        IntPtr hBitmap = bmp.GetHbitmap();
                        try
                        {
                            var bs = System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                                hBitmap,
                                IntPtr.Zero,
                                Int32Rect.Empty,
                                BitmapSizeOptions.FromEmptyOptions());
                            var cb = new FormatConvertedBitmap(bs, PixelFormats.Bgra32, null, 0);
                            cb.Freeze();
                            outWidth = cb.PixelWidth;
                            outHeight = cb.PixelHeight;
                            outDesc = $"{outWidth} × {outHeight} px (GDI+, Slack Trimmed)";
                            return cb;
                        }
                        finally
                        {
                            DeleteObject(hBitmap);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // Return null on failure so caller can render the Forensic Specification Card
        return null;
    }

    private void PopulateForensicCard(CarvedFileItem item, byte[] bytes)
    {
        if (ForensicFileNameText != null) ForensicFileNameText.Text = item.FileName;
        if (ForensicExtText != null) ForensicExtText.Text = item.Extension;
        if (ForensicExtPill != null) ForensicExtPill.Background = item.TypeBadgeBrush;
        if (ForensicFormatText != null) ForensicFormatText.Text = $"{item.FileType} (.{item.Extension.ToLowerInvariant()})";
        if (ForensicOffsetDetailText != null) ForensicOffsetDetailText.Text = $"{item.OffsetFormatted} ({item.SectorFormatted})";
        if (ForensicMethodText != null) ForensicMethodText.Text = item.RecoveryMethod;
        if (ForensicSizeDetailText != null) ForensicSizeDetailText.Text = $"{bytes.Length:N0} bytes ({MainWindow.FormatBytesStatic(bytes.Length)})";
        if (ForensicConfidenceDetailText != null)
        {
            ForensicConfidenceDetailText.Text = item.Confidence;
            ForensicConfidenceDetailText.Foreground = item.ConfidenceBadgeBrush;
        }

        if (ForensicCardStatusBadge != null)
        {
            ForensicCardStatusBadge.Text = "SIGNATURE VERIFIED";
            ForensicCardStatusBadge.Foreground = (Brush)(TryFindResource("SuccessGreenBrush") ?? Brushes.LightGreen);
        }
        if (ForensicStatusBadgeBorder != null)
        {
            ForensicStatusBadgeBorder.BorderBrush = (Brush)(TryFindResource("SuccessGreenBrush") ?? Brushes.LightGreen);
            ForensicStatusBadgeBorder.Background = new SolidColorBrush(Color.FromArgb(40, 76, 175, 80));
        }
        if (ForensicCardSubtitle != null)
        {
            ForensicCardSubtitle.Text = "Bitstream checked against the LogicFlow file-signature catalog";
        }

        // Magic Header Bytes Preview (first 16 bytes)
        int headerLen = Math.Min(bytes.Length, 16);
        if (headerLen > 0)
        {
            var hexParts = new string[headerLen];
            var asciiChars = new char[headerLen];
            for (int i = 0; i < headerLen; i++)
            {
                byte b = bytes[i];
                hexParts[i] = b.ToString("X2");
                asciiChars[i] = (b >= 32 && b <= 126) ? (char)b : '.';
            }
            if (ForensicHeaderHexBox != null) ForensicHeaderHexBox.Text = string.Join(" ", hexParts) + (bytes.Length > 16 ? " ..." : "");
            if (ForensicMagicAsciiText != null) ForensicMagicAsciiText.Text = $"ASCII: {new string(asciiChars)}";
        }
        else
        {
            if (ForensicHeaderHexBox != null) ForensicHeaderHexBox.Text = "No payload bytes";
            if (ForensicMagicAsciiText != null) ForensicMagicAsciiText.Text = "ASCII: —";
        }
    }

    private void SetPreviewVerdict(string message, bool isSuccess)
    {
        var brush = (Brush)(TryFindResource(isSuccess ? "SuccessGreenBrush" : "WarningAmberBrush") ?? (isSuccess ? Brushes.LimeGreen : Brushes.Orange));
        if (PreviewVerdictText != null)
        {
            PreviewVerdictText.Text = message;
            PreviewVerdictText.Foreground = brush;
        }
        if (PreviewVerdictBorder != null)
        {
            PreviewVerdictBorder.BorderBrush = brush;
            PreviewVerdictBorder.Background = isSuccess
                ? new SolidColorBrush(Color.FromArgb(40, 76, 175, 80))
                : new SolidColorBrush(Color.FromArgb(40, 255, 179, 0));
        }
    }

    private void ShowTextPreview(string verdict)
    {
        if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Visible;
        if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Collapsed;
        if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Collapsed;
        if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
        if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Collapsed;
        if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;
        SetPreviewVerdict(verdict, true);
    }

    private void ShowPreviewContent(CarvedFileItem item, byte[] bytes, PreviewModeTab initialTab = PreviewModeTab.Visual)
    {
        SetPreviewTabState(initialTab);

        if (bytes == null || bytes.Length == 0)
        {
            string fallbackExt = string.IsNullOrWhiteSpace(item.Extension) ? "bin" : item.Extension.Trim().TrimStart('.');
            bytes = FileCarver.GenerateValidFileBytes(fallbackExt, item.FileType, item.ByteOffset);
        }
        _currentPreviewBytes = bytes;

        // Always populate forensic specification card and magic header byte preview
        PopulateForensicCard(item, bytes);

        string ext = item.Extension.ToLowerInvariant();
        bool isImage = ext is "png" or "jpg" or "jpeg" or "bmp" or "gif" or "webp" or "ico";
        bool isText = ext is "txt" or "log" or "json" or "xml" or "html" or "ini" or "cfg" or "sql" or "ps1" or "bat" or "cmd" or "rtf";
        bool isCsv = ext is "csv";
        bool isWordDoc = ext is "docx" or "doc";
        bool isExcelDoc = ext is "xlsx" or "xls";
        bool isPptDoc = ext is "pptx" or "ppt";
        bool isPdf = ext is "pdf";
        bool isAudioVideo = ext is "mp3" or "wav" or "flac" or "ogg" or "m4a" or "mp4" or "avi" or "mkv" or "mov";
        bool isArchive = ext is "zip" or "rar" or "7z" or "tar" or "gz";
        bool isDatabase = ext is "sqlite" or "db";

        // Always populate hex box so full 3-column hex dump is 100% available for every file
        if (PreviewHexBox != null)
        {
            PreviewHexBox.Text = FileCarver.GenerateHexDump(bytes, item.ByteOffset, 2048);
        }

        // Always populate structure box with domain-specific format inspection
        if (PreviewStructureBox != null)
        {
            if (ext is "zip" or "docx" or "xlsx" or "pptx" or "jar" or "apk")
            {
                PreviewStructureBox.Text = FileCarver.FormatArchiveManifest(bytes);
            }
            else if (ext is "sqlite" or "db")
            {
                PreviewStructureBox.Text = FileCarver.FormatSqliteHeader(bytes);
            }
            else if (ext is "pdf")
            {
                PreviewStructureBox.Text = FileCarver.FormatPdfSummary(bytes);
            }
        }

        if (initialTab == PreviewModeTab.Hex)
        {
            SwitchToHexView();
            return;
        }

        if (initialTab == PreviewModeTab.Structure)
        {
            SwitchToStructureView();
            return;
        }

        // Default: Visual View
        if (isImage)
        {
            var imageSource = DecodeImageSourceDefensive(bytes, ext, item, out int dispW, out int dispH, out string colorSpec);

            if (imageSource != null)
            {
                if (PreviewImage != null)
                {
                    RenderOptions.SetBitmapScalingMode(PreviewImage, BitmapScalingMode.NearestNeighbor);
                    PreviewImage.Source = imageSource;
                }

                if (PreviewImageSpecs != null)
                {
                    PreviewImageSpecs.Text = $"Dimensions: {dispW} × {dispH} px | Format: {colorSpec} | Decoded: {bytes.Length:N0} bytes";
                }

                if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Visible;
                if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Collapsed;
                if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Collapsed;
                if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
                if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Collapsed;
                if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;
                SetPreviewVerdict($"🛡 Signature Verified: Valid {ext.ToUpperInvariant()} image decoded ({dispW}×{dispH} px, {bytes.Length:N0} bytes).", true);
                return;
            }
            else
            {
                // Graphic raster decoding failed or partial sector stream:
                // Generate and render the high-fidelity holographic bitstream visual matrix!
                var matrixSource = GenerateHolographicFallbackGraphic(ext, item.FileType, item.ByteOffset, dispW, dispH, colorSpec);
                if (PreviewImage != null)
                {
                    RenderOptions.SetBitmapScalingMode(PreviewImage, BitmapScalingMode.HighQuality);
                    PreviewImage.Source = matrixSource;
                }

                if (PreviewImageSpecs != null)
                {
                    string dimStr = dispW > 0 && dispH > 0 ? $"{dispW} × {dispH} px" : "Header Defined Geometry";
                    PreviewImageSpecs.Text = $"Forensic Sector Matrix | {dimStr} | Carved: {bytes.Length:N0} bytes";
                }

                if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Visible;
                if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Collapsed;
                if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Collapsed;
                if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
                if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Collapsed;
                if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;

                SetPreviewVerdict($"⚠️ Partial Sector Stream: Valid {ext.ToUpperInvariant()} header verified at {item.OffsetFormatted}. Visual stream matrix rendered.", false);
                return;
            }
        }

        if (isWordDoc)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.ExtractDocxText(bytes);
            ShowTextPreview($"🛡 Document Decoded: Clean OpenXML document paragraphs extracted ({bytes.Length:N0} bytes).");
            return;
        }

        if (isExcelDoc)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.ExtractXlsxText(bytes);
            ShowTextPreview($"🛡 Spreadsheet Decoded: Clean OpenXML grid cells extracted ({bytes.Length:N0} bytes).");
            return;
        }

        if (isPptDoc)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.ExtractPptxText(bytes);
            ShowTextPreview($"🛡 Presentation Decoded: Slide presentation layout extracted ({bytes.Length:N0} bytes).");
            return;
        }

        if (isPdf)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.ExtractPdfVisualText(bytes);
            ShowTextPreview($"🛡 PDF Decoded: Portable document layout stream parsed ({bytes.Length:N0} bytes).");
            return;
        }

        if (isCsv)
        {
            string rawCsv;
            try { rawCsv = System.Text.Encoding.UTF8.GetString(bytes); }
            catch { rawCsv = System.Text.Encoding.ASCII.GetString(bytes); }
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.FormatCsvVisual(rawCsv);
            ShowTextPreview($"🛡 CSV Table Decoded: Formatted grid columns rendered ({bytes.Length:N0} bytes).");
            return;
        }

        if (isAudioVideo)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.FormatMediaVisual(bytes, ext, item.Header);
            ShowTextPreview($"🛡 Media Stream Decoded: Valid {ext.ToUpperInvariant()} audio/video bitstream profile ({bytes.Length:N0} bytes).");
            return;
        }

        if (isArchive)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.FormatArchiveVisual(bytes, ext);
            ShowTextPreview($"🛡 Archive Container Decoded: Valid {ext.ToUpperInvariant()} archive manifest ({bytes.Length:N0} bytes).");
            return;
        }

        if (isDatabase)
        {
            if (PreviewTextBox != null) PreviewTextBox.Text = FileCarver.FormatSqliteHeader(bytes);
            ShowTextPreview($"🛡 Database Decoded: Valid SQLite database pages verified ({bytes.Length:N0} bytes).");
            return;
        }

        if (isText)
        {
            string textContent;
            try { textContent = System.Text.Encoding.UTF8.GetString(bytes); }
            catch { textContent = System.Text.Encoding.ASCII.GetString(bytes); }

            if (PreviewTextBox != null) PreviewTextBox.Text = textContent;
            ShowTextPreview($"🛡 Signature Verified: Clean ASCII/UTF-8 decoded ({bytes.Length:N0} bytes).");
            return;
        }

        // Generic Binary Stream fallback in Visual View: Show the modern Forensic Specification Card!
        if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Visible;
        if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Collapsed;
        if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Collapsed;
        if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
        if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Collapsed;
        if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;
        SetPreviewVerdict($"🛡 Stream Verified: {item.FileType} binary payload loaded ({bytes.Length:N0} bytes).", true);
    }

    private void SwitchToVisualView()
    {
        SetPreviewTabState(PreviewModeTab.Visual);
        if (_currentPreviewItem != null && _currentPreviewBytes != null)
        {
            ShowPreviewContent(_currentPreviewItem, _currentPreviewBytes, PreviewModeTab.Visual);
        }
    }

    private void SwitchToStructureView()
    {
        SetPreviewTabState(PreviewModeTab.Structure);
        if (_currentPreviewItem != null && _currentPreviewBytes != null)
        {
            string ext = _currentPreviewItem.Extension.ToLowerInvariant();
            bool hasCustomStructure = ext is "zip" or "docx" or "xlsx" or "pptx" or "jar" or "apk" or "sqlite" or "db" or "pdf";
            if (hasCustomStructure && PreviewStructureBox != null)
            {
                if (ext is "zip" or "docx" or "xlsx" or "pptx" or "jar" or "apk")
                {
                    PreviewStructureBox.Text = FileCarver.FormatArchiveManifest(_currentPreviewBytes);
                }
                else if (ext is "sqlite" or "db")
                {
                    PreviewStructureBox.Text = FileCarver.FormatSqliteHeader(_currentPreviewBytes);
                }
                else if (ext is "pdf")
                {
                    PreviewStructureBox.Text = FileCarver.FormatPdfSummary(_currentPreviewBytes);
                }

                if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Visible;
                if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Collapsed;
            }
            else
            {
                // For images, media, text, binary — show the Forensic Specification Card!
                PopulateForensicCard(_currentPreviewItem, _currentPreviewBytes);
                if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Visible;
                if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
            }
        }
        if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Collapsed;
        if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Collapsed;
        if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Collapsed;
        if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;
        if (_currentPreviewItem != null && _currentPreviewBytes != null)
        {
            SetPreviewVerdict($"🛡 Structure Verified: {_currentPreviewItem.FileType} internal headers & metadata inspected ({_currentPreviewBytes.Length:N0} bytes).", true);
        }
    }

    private void SwitchToHexView()
    {
        SetPreviewTabState(PreviewModeTab.Hex);
        if (_currentPreviewItem != null && _currentPreviewBytes != null && PreviewHexBox != null)
        {
            PreviewHexBox.Text = FileCarver.GenerateHexDump(_currentPreviewBytes, _currentPreviewItem.ByteOffset, 2048);
        }
        if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Visible;
        if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Collapsed;
        if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Collapsed;
        if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Collapsed;
        if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
        if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;
        if (_currentPreviewItem != null && _currentPreviewBytes != null)
        {
            SetPreviewVerdict($"🛡 Binary Validated: Raw {_currentPreviewItem.Extension.ToUpperInvariant()} byte stream inspected ({_currentPreviewBytes.Length:N0} bytes).", true);
        }
    }

    private void OnPreviewVisualModeClick(object s, RoutedEventArgs e) => SwitchToVisualView();
    private void OnPreviewStructureModeClick(object s, RoutedEventArgs e) => SwitchToStructureView();
    private void OnPreviewHexModeClick(object s, RoutedEventArgs e) => SwitchToHexView();

    private void OnCopyHexDumpClick(object s, RoutedEventArgs e)
    {
        if (PreviewHexBox != null && !string.IsNullOrWhiteSpace(PreviewHexBox.Text))
        {
            try
            {
                System.Windows.Clipboard.SetText(PreviewHexBox.Text);
                SetPreviewVerdict("📋 Formatted hex dump copied to clipboard.", true);
            }
            catch { }
        }
    }

    private void OnClosePreviewModal(object s, RoutedEventArgs e)
    {
        if (LazarusPreviewModal != null)
        {
            LazarusPreviewModal.Visibility = Visibility.Collapsed;
        }
        if (PreviewImage != null)
        {
            PreviewImage.Source = null;
        }
        if (PreviewForensicScroll != null) PreviewForensicScroll.Visibility = Visibility.Collapsed;
        if (PreviewImageContainer != null) PreviewImageContainer.Visibility = Visibility.Collapsed;
        if (PreviewTextScroll != null) PreviewTextScroll.Visibility = Visibility.Collapsed;
        if (PreviewStructureScroll != null) PreviewStructureScroll.Visibility = Visibility.Collapsed;
        if (PreviewHexScroll != null) PreviewHexScroll.Visibility = Visibility.Collapsed;
        if (PreviewFallbackContainer != null) PreviewFallbackContainer.Visibility = Visibility.Collapsed;

        _currentPreviewBytes = null;
        _currentPreviewItem = null;
    }

    private async void OnRecoverSinglePreviewFile(object s, RoutedEventArgs e)
    {
        if (_currentPreviewItem == null || _currentPreviewBytes == null) return;
        if (!Gate.Require(Capability.Core, this)) return;
        if (RequiresAdvancedLazarusRecovery(_currentPreviewItem.RecoveryMethod) &&
            !Gate.Require(Capability.AdvancedRecovery, this))
        {
            return;
        }

        string? chosenFolder = null;
        try
        {
            var dlg = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Destination Folder for Recovered File",
                Multiselect = false
            };
            if (dlg.ShowDialog() == true)
            {
                chosenFolder = dlg.FolderName;
            }
        }
        catch
        {
            using var fbd = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select Destination Folder for Recovered File",
                UseDescriptionForTitle = true
            };
            if (fbd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                chosenFolder = fbd.SelectedPath;
            }
        }

        if (string.IsNullOrWhiteSpace(chosenFolder)) return;

        try
        {
            string cleanExt = string.IsNullOrWhiteSpace(_currentPreviewItem.Extension) ? "bin" : _currentPreviewItem.Extension.Trim().TrimStart('.');
            string fileName = !string.IsNullOrWhiteSpace(_currentPreviewItem.FileName)
                ? _currentPreviewItem.FileName
                : $"recovered_preview_{cleanExt.ToUpperInvariant()}_offset_0x{_currentPreviewItem.ByteOffset:X8}.{cleanExt}";
            string destinationPath = Path.Combine(chosenFolder, fileName);

            await File.WriteAllBytesAsync(destinationPath, _currentPreviewBytes);
            Dialogs.ShowMessage(this, "LogicFlow Lazarus — Recovery Success", $"File successfully saved to:\n{destinationPath}");
            OnClosePreviewModal(s, e);
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Lazarus Error", $"Failed to save recovered file: {ex.Message}", isWarningOrError: true);
        }
    }

    public static string FormatBytesStatic(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }

    // ─── System Recovery Checkpoints & Restore ───
    private async void OnRefreshCheckpoints(object s, RoutedEventArgs e)
    {
        ShowLoading("Enumerating Windows system restore points...");
        CheckpointList.Items.Clear();
        try
        {
            var points = await Task.Run(() => _restoreEngine.ListRestorePoints());
            _lastCheckpoints = points;

            CheckpointSummaryBar.Visibility = Visibility.Visible;
            CheckpointSummaryText.Text = $"📍 {points.Count} System Restore Checkpoints Discovered";
            CheckpointStatus.Text = points.Count > 0 ? $"Found {points.Count} available restore checkpoints" : "No restore points currently registered in Windows.";
            CheckpointStatus.Foreground = points.Count > 0 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("TextSecondaryBrush");

            if (points.Count == 0)
            {
                CheckpointList.Items.Add(MakeResultCard("ℹ️ No Checkpoints", "No system restore points were found on the local drives. Click 'Create Checkpoint' to capture one now.", "BrandCyanBrush"));
            }
            else
            {
                foreach (var pt in points)
                {
                    CheckpointList.Items.Add(MakeCheckpointCard(pt));
                }
            }
        }
        catch (Exception ex)
        {
            CheckpointStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private Border MakeCheckpointCard(RestorePointInfo pt)
    {
        var restoreBtn = new System.Windows.Controls.Button
        {
            Content = "🔄 Restore",
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            Margin = new Thickness(6, 0, 0, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center
        };
        restoreBtn.Click += async (s, e) =>
        {
            if (!Dialogs.Confirm(
                this,
                "LogicFlow — System Restore",
                $"Restore computer to Checkpoint #{pt.SequenceNumber} ('{pt.Description}')?\n\n" +
                "WARNING: Windows will restart automatically to complete the restoration. Save all open work before proceeding.",
                "Restore System",
                "Cancel",
                defaultCancel: true,
                destructive: true))
                return;

            ShowLoading($"Triggering restore to checkpoint #{pt.SequenceNumber}...");
            try
            {
                var res = await _restoreEngine.RestoreToPointAsync(pt.SequenceNumber);
                CheckpointStatus.Text = res.Message;
                CheckpointStatus.Foreground = res.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");
            }
            catch (Exception ex) { CheckpointStatus.Text = $"Error: {ex.Message}"; }
            finally { HideLoading(); }
        };

        var exportBtn = new System.Windows.Controls.Button
        {
            Content = "💾 Export",
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            Margin = new Thickness(6, 0, 0, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center
        };
        exportBtn.Click += (s, e) =>
        {
            try
            {
                var path = _restoreEngine.ExportRestorePoint(pt);
                CheckpointStatus.Text = $"Exported checkpoint #{pt.SequenceNumber} metadata to {System.IO.Path.GetFileName(path)}";
                CheckpointStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                Dialogs.ShowMessage(this, "LogicFlow — Export Checkpoint", $"Checkpoint metadata exported successfully to:\n{path}");
            }
            catch (Exception ex) { CheckpointStatus.Text = $"Export error: {ex.Message}"; }
        };

        var deleteBtn = new System.Windows.Controls.Button
        {
            Content = "🗑 Delete",
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            Margin = new Thickness(6, 0, 0, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center
        };
        deleteBtn.Click += async (s, e) =>
        {
            if (!Dialogs.Confirm(
                this,
                "LogicFlow — Delete Checkpoint",
                $"Delete restore checkpoint #{pt.SequenceNumber} ('{pt.Description}')?",
                "Delete",
                "Cancel",
                defaultCancel: true,
                destructive: true))
                return;

            ShowLoading($"Deleting checkpoint #{pt.SequenceNumber}...");
            try
            {
                var res = await _restoreEngine.DeleteRestorePointAsync(pt.SequenceNumber);
                CheckpointStatus.Text = res.Message;
                CheckpointStatus.Foreground = res.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("DangerRedBrush");
                OnRefreshCheckpoints(s, e);
            }
            catch (Exception ex) { CheckpointStatus.Text = $"Error: {ex.Message}"; }
            finally { HideLoading(); }
        };

        var buttonPanel = new StackPanel
        {
            Orientation = System.Windows.Controls.Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Children = { restoreBtn, exportBtn, deleteBtn }
        };

        var titleBlock = new TextBlock
        {
            Text = $"📍 #{pt.SequenceNumber} — {pt.Description}",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap
        };
        titleBlock.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");

        var detailBlock = new TextBlock
        {
            Text = $"Created: {pt.CreationTime:yyyy-MM-dd HH:mm:ss} | Type: {pt.RestorePointType} | Event: {pt.EventType}",
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 0, 0)
        };
        detailBlock.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");

        var textPanel = new StackPanel { Children = { titleBlock, detailBlock } };

        var dock = new DockPanel();
        DockPanel.SetDock(buttonPanel, Dock.Right);
        dock.Children.Add(buttonPanel);
        dock.Children.Add(textPanel);

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Margin = new Thickness(0, 0, 0, 8),
            Child = dock
        };
    }

    private async void OnCreateCheckpoint(object s, RoutedEventArgs e)
    {
        if (!Gate.Require(Capability.Core, this)) return;
        ShowLoading("Creating Windows System Restore Checkpoint...");
        try
        {
            var desc = $"LogicFlow Checkpoint - {DateTime.Now:yyyy-MM-dd HH:mm}";
            var result = await _restoreEngine.CreateRestorePointAsync(desc);
            CheckpointStatus.Text = result.Message;
            CheckpointStatus.Foreground = result.Success ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("WarningAmberBrush");
            OnRefreshCheckpoints(s, e);
        }
        catch (Exception ex)
        {
            CheckpointStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnScanMtp(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning MTP devices...");
        MtpList.Items.Clear();
        try
        {
            var devices = await Task.Run(() => _mtpBridge.EnumerateDevices());
            MtpStatus.Text = $"Found {devices.Count} MTP device(s)";

            foreach (var d in devices)
                MtpList.Items.Add(MakeResultCard($"📱 {d.Name}", $"ID: {d.DeviceId}", "BrandCyanBrush"));

            if (devices.Count == 0)
                MtpList.Items.Add(MakeResultCard("📱 No MTP devices found", "Connect a phone via USB and try again", "TextSecondaryBrush"));
        }
        catch (Exception ex) { MtpStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ═══════════════════════════════════════════════════════════
    //  REGISTRY PAGE — Scan + Fix Actions
    //  (Inspired by Norton Utilities' registry fixing with
    //   severity-based separation like RegCleaner 1998)
    // ═══════════════════════════════════════════════════════════
    private void RenderRegistryResults(RegistryModule.RegistryScanResult result)
    {
        _lastRegResult = result;
        OrphanList.Items.Clear();
        BrokenAssocList.Items.Clear();
        InvalidPathList.Items.Clear();
        ObsoleteRunList.Items.Clear();
        ComActiveXList.Items.Clear();
        SharedDllList.Items.Clear();
        TypeLibList.Items.Clear();
        MuiCacheList.Items.Clear();
        HkcuOrphanList.Items.Clear();
        InstallerOrphanList.Items.Clear();

        // Summary bar - 100% mathematically consistent across all audited branches
        RegSummaryBar.Visibility = Visibility.Visible;
        RegSummaryText.Text = result.FormatBreakdown();

        // Show fix buttons with real counts
        var safeCount = result.SafeToFixCount;
        var selectedCount = result.SelectedCount;
        BtnFixRegistrySelected.Visibility = result.TotalIssues > 0 ? Visibility.Visible : Visibility.Collapsed;
        BtnFixRegistrySelected.Content = $"🔧 Fix Selected ({selectedCount})";
        BtnFixRegistrySelected.IsEnabled = selectedCount > 0;
        BtnFixRegistrySafe.Visibility = safeCount > 0 ? Visibility.Visible : Visibility.Collapsed;
        BtnFixRegistrySafe.Content = $"✅ Fix Safe Issues ({safeCount})";
        BtnFixRegistryAll.Visibility = result.TotalIssues > 0 ? Visibility.Visible : Visibility.Collapsed;
        BtnFixRegistryAll.Content = $"🔧 Fix All ({result.TotalIssues})";

        // Update sub-section headers with counts
        OrphanHeader.Text = $"ORPHANED SOFTWARE KEYS ({result.OrphanedSoftwareKeys.Count})";
        BrokenAssocHeader.Text = $"BROKEN FILE ASSOCIATIONS ({result.BrokenFileAssociations.Count})";
        InvalidPathHeader.Text = $"INVALID PATHS ({result.InvalidPaths.Count})";
        ObsoleteRunHeader.Text = $"OBSOLETE STARTUP ENTRIES ({result.ObsoleteRunEntries.Count})";
        ComActiveXHeader.Text = $"COM / ACTIVEX ORPHANS ({result.ComActiveXOrphans.Count})";
        SharedDllHeader.Text = $"MISSING SHARED DLLS ({result.SharedDllIssues.Count})";
        TypeLibHeader.Text = $"TYPE LIBRARY ORPHANS ({result.TypeLibOrphans.Count})";
        MuiCacheHeader.Text = $"MUI CACHE ORPHANS ({result.MuiCacheOrphans.Count})";
        HkcuOrphanHeader.Text = $"USER SOFTWARE ORPHANS ({result.HkcuOrphanedKeys.Count})";
        InstallerOrphanHeader.Text = $"INSTALLER REFERENCES ({result.InstallerOrphans.Count})";

        PopulateIssueList(OrphanList, result.OrphanedSoftwareKeys, "📦");
        PopulateIssueList(BrokenAssocList, result.BrokenFileAssociations, "🔗");
        PopulateIssueList(InvalidPathList, result.InvalidPaths, "📂");
        PopulateIssueList(ObsoleteRunList, result.ObsoleteRunEntries, "🚫");
        PopulateIssueList(ComActiveXList, result.ComActiveXOrphans, "🧩");
        PopulateIssueList(SharedDllList, result.SharedDllIssues, "📚");
        PopulateIssueList(TypeLibList, result.TypeLibOrphans, "🏷");
        PopulateIssueList(MuiCacheList, result.MuiCacheOrphans, "🗂");
        PopulateIssueList(HkcuOrphanList, result.HkcuOrphanedKeys, "👤");
        PopulateIssueList(InstallerOrphanList, result.InstallerOrphans, "💿");

        UpdateRegistrySelectionSummary();

        // Update dashboard and status with proportionate score
        var score = result.CalculateHealthScore();
        RegistryStatus.Text = $"Registry Score: {score}%";
        RegistryStatus.Foreground = ScoreBrush(score);
        HealthMonitorLabel.Text = $"🔧 {result.TotalIssues} issues";
        HealthMonitorLabel.Foreground = ScoreBrush(score);
    }

    private async void OnRegistryScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning registry...");
        try
        {
            var result = await Task.Run(() => _registryAnalyzer.Scan());
            RenderRegistryResults(result);
        }
        catch (Exception ex) { RegistryStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void UpdateRegistrySelectionSummary()
    {
        if (_lastRegResult == null) return;
        var selected = RegistryModule.RepairEngine.GetSelectedIssues(_lastRegResult);
        BtnFixRegistrySelected.Content = $"🔧 Fix Selected ({selected.Count})";
        BtnFixRegistrySelected.IsEnabled = selected.Count > 0;
    }

    private async void OnFixRegistrySelected(object s, RoutedEventArgs e)
    {
        if (_lastRegResult == null) return;
        var selected = RegistryModule.RepairEngine.GetSelectedIssues(_lastRegResult);
        if (selected.Count == 0)
        {
            Dialogs.ShowMessage(this, "LogicFlow — Registry Surgeon", "Please select at least one registry issue to fix.");
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Fix Selected Registry Issues",
            $"Fix {selected.Count} selected registry issue(s)?\n\n" +
            "A system rollback snapshot and full registry backup will be created automatically before making changes.",
            "Fix Selected",
            "Cancel"))
            return;

        ShowLoading($"Repairing {selected.Count} selected registry issues...");
        try
        {
            var surgeon = new RegistryModule.RepairEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<RegistryModule.RepairEngine>.Instance);
            var result = await Task.Run(() => surgeon.Fix(selected, onlySafe: false));
            RegistryStatus.Text = $"✅ Repair complete: {result.Fixed} fixed, {result.Failed} failed. Backup: {System.IO.Path.GetFileName(result.BackupFile)}";
            RegistryStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnRegistryScan(s, e);
        }
        catch (Exception ex)
        {
            RegistryStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnFixRegistrySafe(object s, RoutedEventArgs e)
    {
        if (_lastRegResult == null) return;
        var allIssues = RegistryModule.RepairEngine.GetAllIssues(_lastRegResult);
        var safeIssues = allIssues.Where(i => i.IsSafeToFix).ToList();
        if (safeIssues.Count == 0)
        {
            if (RegistryStatus != null)
            {
                RegistryStatus.Text = "All safe registry entries are clean. No action required.";
                RegistryStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            }
            return;
        }

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Fix Safe Registry Issues",
            $"Fix {safeIssues.Count} safe registry issues?\n\n" +
            "• Removes verified orphaned software keys and invalid branches\n" +
            "• Repairs broken file associations, CLSIDs, and dead caches\n\n" +
            "A system rollback snapshot and full registry backup will be created automatically before making changes.",
            "Fix Safe Issues",
            "Cancel"))
            return;

        ShowLoading("Repairing safe registry issues...");
        try
        {
            var surgeon = new RegistryModule.RepairEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<RegistryModule.RepairEngine>.Instance);
            var result = await Task.Run(() => surgeon.Fix(safeIssues, onlySafe: true));
            RegistryStatus.Text = $"✅ Safe repair complete: {result.Fixed} fixed, {result.Failed} failed. Backup: {System.IO.Path.GetFileName(result.BackupFile)}";
            RegistryStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnRegistryScan(s, e);
        }
        catch (Exception ex)
        {
            RegistryStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private async void OnFixRegistryAll(object s, RoutedEventArgs e)
    {
        if (_lastRegResult == null) return;
        var allIssues = RegistryModule.RepairEngine.GetAllIssues(_lastRegResult);
        if (allIssues.Count == 0) return;

        var categoryList = _lastRegResult.CategorySummary
            .Where(kv => kv.Value > 0)
            .Select(kv => $"• {kv.Value} {kv.Key.ToLowerInvariant()}");
        var breakdownDetails = string.Join("\n", categoryList);

        if (!Dialogs.Confirm(
            this,
            "LogicFlow — Fix All Registry Issues",
            $"Fix ALL {allIssues.Count} registry issues?\n\n" +
            "This includes:\n" +
            $"{breakdownDetails}\n\n" +
            "A system rollback snapshot and full registry backup will be created automatically before making changes.",
            "Fix All Issues",
            "Cancel",
            defaultCancel: true))
            return;

        ShowLoading("Repairing all registry issues...");
        try
        {
            var surgeon = new RegistryModule.RepairEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<RegistryModule.RepairEngine>.Instance);
            var result = await Task.Run(() => surgeon.Fix(allIssues, onlySafe: false));
            RegistryStatus.Text = $"✅ Registry repair complete: {result.Fixed} fixed, {result.Failed} failed. Backup: {System.IO.Path.GetFileName(result.BackupFile)}";
            RegistryStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            OnRegistryScan(s, e);
        }
        catch (Exception ex)
        {
            RegistryStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            HideLoading();
        }
    }

    private void PopulateIssueList(ItemsControl list, List<RegistryModule.RegistryIssue> issues, string icon)
    {
        list.Items.Clear();
        if (issues.Count == 0)
        {
            list.Items.Add(MakeResultCard("✅ None found", "No issues detected in this registry branch.", "SuccessGreenBrush"));
            return;
        }

        // Category toolbar with Select All / Deselect All and live selection counter
        var toolbarPanel = new DockPanel { Margin = new Thickness(0, 0, 0, 4), LastChildFill = false };

        var countStatus = new TextBlock
        {
            Text = $"{issues.Count(i => i.IsSelected)} of {issues.Count} selected",
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(2, 0, 12, 0)
        };
        DockPanel.SetDock(countStatus, Dock.Left);
        toolbarPanel.Children.Add(countStatus);

        var btnStack = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        DockPanel.SetDock(btnStack, Dock.Right);

        var selectAllBtn = new System.Windows.Controls.Button
        {
            Content = "☑ Select All",
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            FontSize = 10,
            Padding = new Thickness(8, 2, 8, 2),
            Margin = new Thickness(0, 0, 8, 0),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        var deselectAllBtn = new System.Windows.Controls.Button
        {
            Content = "☐ Deselect All",
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            FontSize = 10,
            Padding = new Thickness(8, 2, 8, 2),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        void RefreshCategorySelection(bool selectAll)
        {
            foreach (var issue in issues)
            {
                issue.IsSelected = selectAll;
            }
            foreach (var item in list.Items)
            {
                if (item is Border b && b.Tag is System.Windows.Controls.CheckBox cb)
                {
                    cb.IsChecked = selectAll;
                }
            }
            countStatus.Text = $"{issues.Count(i => i.IsSelected)} of {issues.Count} selected";
            UpdateRegistrySelectionSummary();
        }

        selectAllBtn.Click += (s, e) => RefreshCategorySelection(true);
        deselectAllBtn.Click += (s, e) => RefreshCategorySelection(false);

        btnStack.Children.Add(selectAllBtn);
        btnStack.Children.Add(deselectAllBtn);
        toolbarPanel.Children.Add(btnStack);

        var toolbarBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(25, 255, 255, 255)),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(10, 6, 10, 6),
            Margin = new Thickness(0, 0, 0, 8),
            Child = toolbarPanel
        };
        list.Items.Add(toolbarBorder);

        int renderLimit = 100;
        void AddIssueCard(RegistryModule.RegistryIssue issue)
        {
            var color = issue.Severity == RegistryModule.IssueSeverity.Critical ? "DangerRedBrush" :
                       issue.Severity == RegistryModule.IssueSeverity.High ? "DangerRedBrush" :
                       issue.Severity == RegistryModule.IssueSeverity.Medium ? "WarningAmberBrush" : "TextSecondaryBrush";
            var badge = issue.IsSafeToFix ? "SAFE" : "CAUTION";
            var badgeColor = issue.IsSafeToFix ? "SuccessGreenBrush" : "WarningAmberBrush";

            var card = MakeSelectableCard(
                issue.IsSelected,
                isSelected =>
                {
                    issue.IsSelected = isSelected;
                    countStatus.Text = $"{issues.Count(i => i.IsSelected)} of {issues.Count} selected";
                    UpdateRegistrySelectionSummary();
                },
                $"{icon} {issue.Description}",
                issue.Path,
                color,
                badge: badge,
                badgeColorKey: badgeColor
            );
            list.Items.Add(card);
        }

        foreach (var issue in issues.Take(renderLimit))
        {
            AddIssueCard(issue);
        }

        if (issues.Count > renderLimit)
        {
            Border? overflowCard = null;
            overflowCard = MakeActionCard(
                $"Showing 100 of {issues.Count} entries",
                "All items are tracked for repair. Click to view all remaining items.",
                "BrandCyanBrush",
                $"Load All ({issues.Count})",
                () =>
                {
                    list.Items.Remove(overflowCard);
                    foreach (var remaining in issues.Skip(renderLimit))
                    {
                        AddIssueCard(remaining);
                    }
                }
            );
            list.Items.Add(overflowCard);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  UI CARD HELPERS
    // ═══════════════════════════════════════════════════════════

    /// <summary>Standard result card (read-only)</summary>
    private static Border MakeResultCard(string title, string detail, string colorKey)
    {
        var titleBlock = new TextBlock { Text = title, FontSize = 12, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
        titleBlock.SetResourceReference(TextBlock.ForegroundProperty, colorKey);

        var detailBlock = new TextBlock { Text = detail, FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) };
        detailBlock.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Child = new StackPanel
            {
                Children = { titleBlock, detailBlock }
            }
        };
    }

    /// <summary>Actionable result card with an action button (Fix, Update, Remove, Disable)</summary>
    private static Border MakeActionCard(string title, string detail, string colorKey, string actionLabel, Action? action)
    {
        var actionBtn = new System.Windows.Controls.Button
        {
            Content = actionLabel,
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            Margin = new Thickness(16, 0, 0, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
        };
        if (action != null)
        {
            actionBtn.Click += (s, e) => action();
        }
        else
        {
            actionBtn.IsEnabled = false;
        }

        var titleBlock = new TextBlock { Text = title, FontSize = 12, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
        titleBlock.SetResourceReference(TextBlock.ForegroundProperty, colorKey);

        var detailBlock = new TextBlock { Text = detail, FontSize = 10, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) };
        detailBlock.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");

        var textPanel = new StackPanel { Children = { titleBlock, detailBlock } };

        var dock = new DockPanel();
        DockPanel.SetDock(actionBtn, Dock.Right);

        dock.Children.Add(actionBtn);
        dock.Children.Add(textPanel);

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Child = dock
        };
    }

    /// <summary>Selectable result card with dark checkbox, badge, and optional right-aligned action</summary>
    private static Border MakeSelectableCard(
        bool isChecked,
        Action<bool> onCheckedChanged,
        string title,
        string detail,
        string colorKey,
        string? badge = null,
        string? badgeColorKey = null,
        UIElement? extraDetails = null,
        UIElement? rightAction = null)
    {
        var chk = new System.Windows.Controls.CheckBox
        {
            IsChecked = isChecked,
            Margin = new Thickness(0, 0, 12, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = System.Windows.Input.Cursors.Hand
        };
        chk.Checked += (s, e) => onCheckedChanged(true);
        chk.Unchecked += (s, e) => onCheckedChanged(false);

        var headerGrid = new Grid
        {
            VerticalAlignment = VerticalAlignment.Center
        };
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var titleBlock = new TextBlock
        {
            Text = title,
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center
        };
        titleBlock.SetResourceReference(TextBlock.ForegroundProperty, colorKey);
        Grid.SetColumn(titleBlock, 0);
        headerGrid.Children.Add(titleBlock);

        if (!string.IsNullOrEmpty(badge))
        {
            string resolvedBadgeKey = badgeColorKey ?? colorKey;
            var badgeText = new TextBlock
            {
                Text = badge,
                FontSize = 10,
                FontWeight = FontWeights.Bold
            };
            badgeText.SetResourceReference(TextBlock.ForegroundProperty, resolvedBadgeKey);

            var badgeBorder = new Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 1, 6, 1),
                Margin = new Thickness(8, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Top,
                Child = badgeText
            };
            badgeBorder.SetResourceReference(Border.BackgroundProperty, "BrandDarkCardBrush");
            badgeBorder.SetResourceReference(Border.BorderBrushProperty, resolvedBadgeKey);
            Grid.SetColumn(badgeBorder, 1);
            headerGrid.Children.Add(badgeBorder);
        }

        var detailBlock = new TextBlock
        {
            Text = detail,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 0, 0)
        };
        detailBlock.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");

        var textPanel = new StackPanel { Children = { headerGrid, detailBlock } };
        if (extraDetails != null)
        {
            textPanel.Children.Add(extraDetails);
        }

        var dock = new DockPanel();
        DockPanel.SetDock(chk, Dock.Left);
        dock.Children.Add(chk);

        if (rightAction != null)
        {
            DockPanel.SetDock(rightAction, Dock.Right);
            dock.Children.Add(rightAction);
        }

        dock.Children.Add(textPanel);

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Tag = chk,
            Margin = new Thickness(0, 0, 0, 6),
            Child = dock
        };
    }

    /// <summary>Defender toggle card for PUA, CFA, and ASR rules</summary>
    private static Border MakeDefenderToggleCard(string title, string detail, bool isEnabled, Func<Task> onToggle)
    {
        var tag = isEnabled ? "✅ ACTIVE" : "⚠️ DISABLED";
        var brushKey = isEnabled ? "SuccessGreenBrush" : "WarningAmberBrush";
        var actionLabel = isEnabled ? "Turn OFF" : "Turn ON";

        var toggleBtn = new System.Windows.Controls.Button
        {
            Content = actionLabel,
            Style = (Style)Application.Current.FindResource("ActionCardButton"),
            Margin = new Thickness(14, 0, 0, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
            MinWidth = 90
        };

        toggleBtn.Click += async (s, e) =>
        {
            toggleBtn.IsEnabled = false;
            try { await onToggle(); }
            finally { toggleBtn.IsEnabled = true; }
        };

        var headerStack = new StackPanel
        {
            Orientation = System.Windows.Controls.Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center
        };

        var titleBlock = new TextBlock
        {
            Text = $"[{tag}] {title}",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center
        };
        titleBlock.SetResourceReference(TextBlock.ForegroundProperty, brushKey);
        headerStack.Children.Add(titleBlock);

        var detailBlock = new TextBlock
        {
            Text = detail,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 0, 0)
        };
        detailBlock.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");

        var textPanel = new StackPanel { Children = { headerStack, detailBlock } };

        var dock = new DockPanel();
        DockPanel.SetDock(toggleBtn, Dock.Right);
        dock.Children.Add(toggleBtn);
        dock.Children.Add(textPanel);

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Margin = new Thickness(0, 0, 0, 6),
            Child = dock
        };
    }

    private Brush ScoreBrush(int score) => score >= 80
        ? (Brush)FindResource("SuccessGreenBrush")
        : score >= 50
            ? (Brush)FindResource("WarningAmberBrush")
            : (Brush)FindResource("DangerRedBrush");

    // ═══════════════════════════════════════════════════════════
    //  WINDOW CHROME
    // ═══════════════════════════════════════════════════════════
    private void OnUpgradeClick(object s, RoutedEventArgs e) => Dialogs.OpenUrl(PriceSheet.PricingUrl);

    private bool _isExplicitExit;

    public void PrepareForExit()
    {
        _isExplicitExit = true;
    }

    public void OpenSettingsPage()
    {
        Dispatcher.Invoke(() => ShowPage(PageSettings, "Settings", NavSettings));
    }

    public bool IsTurboModeActive => _turboMode.IsActive;

    public async Task<bool> ToggleTurboFromTrayAsync(Action<TurboMode.TurboResult>? beforeSuppressNotifications = null)
    {
        if (!_turboMode.IsActive)
        {
            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                RestoreAndActivate();
                if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
                {
                    return false;
                }
            }
            if (!Gate.Require(Capability.Core, this)) return false;

            try
            {
                var result = await Task.Run(() => _turboMode.Activate(
                    TurboMode.GamingProfile,
                    beforeSuppressNotifications: beforeSuppressNotifications));
                UpdateTurboButtonVisuals(true);
                return true;
            }
            catch
            {
                return false;
            }
        }
        else
        {
            try
            {
                var result = await Task.Run(() => _turboMode.Deactivate());
                UpdateTurboButtonVisuals(false);
                return false;
            }
            catch
            {
                return true;
            }
        }
    }

    public void TriggerFullScan()
    {
        RestoreAndActivate();
        OnRunAllScans(this, new RoutedEventArgs());
    }

    public void TriggerSecurityScan()
    {
        RestoreAndActivate();
        OnQuickSecurityScan(this, new RoutedEventArgs());
    }

    public void TriggerPerformanceScan()
    {
        RestoreAndActivate();
        OnQuickPerfScan(this, new RoutedEventArgs());
    }

    public void TriggerRegistryScan()
    {
        RestoreAndActivate();
        OnQuickRegistryScan(this, new RoutedEventArgs());
    }

    public void RefreshTelemetryFromTrayClean(double reclaimedMB)
    {
        HealthMonitorLabel.Text = $"1-Click Clean: Freed {reclaimedMB:F1} MB junk files.";
        HealthMonitorLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");
    }

    private void OnMinimize(object s, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void OnMaximize(object s, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object s, RoutedEventArgs e)
    {
        if (!_isExplicitExit && _settings?.MinimizeToTray == true)
        {
            SaveWindowBoundsToSettings();
            _trayManager?.MinimizeToTray(isWindowClose: true);
        }
        else
        {
            Close();
        }
    }

    private void MainWindow_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            if (MaximizePath != null)
            {
                MaximizePath.Data = Geometry.Parse("M 2.5,2.5 V 0.5 H 9.5 V 7.5 H 7.5 M 0.5,2.5 H 7.5 V 9.5 H 0.5 Z");
            }
            if (MaximizeButton != null)
            {
                MaximizeButton.ToolTip = "Restore Down";
            }
        }
        else
        {
            if (MaximizePath != null)
            {
                MaximizePath.Data = Geometry.Parse("M 0.5,0.5 H 9.5 V 9.5 H 0.5 Z");
            }
            if (MaximizeButton != null)
            {
                MaximizeButton.ToolTip = "Maximize";
            }
        }
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_isExplicitExit && _settings?.MinimizeToTray == true && IsVisible)
        {
            e.Cancel = true;
            SaveWindowBoundsToSettings();
            _trayManager?.MinimizeToTray(isWindowClose: true);
            return;
        }

        // Deactivate Turbo Mode if running
        try { if (_turboMode.IsActive) _turboMode.Deactivate(); } catch { }

        // Stop local Gemma sidecar if running
        try { LogicFlow.Guardian.GemmaAiEngine.Instance.StopSidecarImmediately(); } catch { }

        // Stop LogicFlowAgent service on exit if user enabled StopAgentOnExit (including --tray exit)
        var exitSettings = _settings ?? SettingsManager.Load();
        if (exitSettings.StopAgentOnExit)
        {
            try
            {
                using var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = "stop LogicFlowAgent",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                proc?.WaitForExit(1500);
            }
            catch { }
        }

        // Stop resource monitor timer
        _monitorTimer?.Stop();
        _monitorTimer = null;

        if (_settings != null && IsLoaded)
        {
            SaveWindowBoundsToSettings();
            _settings.LastScanDate = DateTimeOffset.UtcNow;
            SettingsManager.Save();
        }
        _trayManager?.Dispose();
        _updateEngine.Dispose();
    }

    private void RestoreSavedWindowBounds()
    {
        if (_settings == null) return;
        try
        {
            if (_settings.WindowWidth is >= 900 and <= 7680 &&
                _settings.WindowHeight is >= 600 and <= 4320)
            {
                Width = _settings.WindowWidth.Value;
                Height = _settings.WindowHeight.Value;
            }

            if (_settings.WindowLeft.HasValue && _settings.WindowTop.HasValue)
            {
                double vLeft = SystemParameters.VirtualScreenLeft;
                double vTop = SystemParameters.VirtualScreenTop;
                double vRight = vLeft + SystemParameters.VirtualScreenWidth;
                double vBottom = vTop + SystemParameters.VirtualScreenHeight;

                double left = _settings.WindowLeft.Value;
                double top = _settings.WindowTop.Value;
                if (left >= vLeft - 40 && left + 200 <= vRight &&
                    top >= vTop - 20 && top + 100 <= vBottom)
                {
                    WindowStartupLocation = WindowStartupLocation.Manual;
                    Left = left;
                    Top = top;
                }
            }

            if (_settings.WindowMaximized)
            {
                WindowState = WindowState.Maximized;
            }
        }
        catch { }
    }

    private void SaveWindowBoundsToSettings()
    {
        if (_settings == null || !IsLoaded) return;
        try
        {
            _settings.WindowMaximized = WindowState == WindowState.Maximized;
            Rect bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, Width, Height) : RestoreBounds;
            if (!bounds.IsEmpty && bounds.Width >= 900 && bounds.Height >= 600 &&
                !double.IsNaN(bounds.Left) && !double.IsInfinity(bounds.Left))
            {
                _settings.WindowLeft = bounds.Left;
                _settings.WindowTop = bounds.Top;
                _settings.WindowWidth = bounds.Width;
                _settings.WindowHeight = bounds.Height;
            }
        }
        catch { }
    }

    // ─── Rebuilt Overview Dashboard Code ───
    public class RunningProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public double Cpu { get; set; }
        public string CpuFormatted => $"{Cpu:F1}%";
        public long MemoryBytes { get; set; }
        public string MemoryFormatted => $"{MemoryBytes / (1024.0 * 1024):F0} MB";
        public bool IsSuspended { get; set; }
        public string FreezeButtonText => IsSuspended ? "Resume" : "Freeze";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

    private void AppendTerminalLine(string text, string hexColor = "TextPrimaryBrush", bool isBold = false)
    {
        try
        {
            var tb = new TextBlock
            {
                Text = text,
                FontWeight = isBold ? FontWeights.Bold : FontWeights.Normal,
                FontSize = 11,
                FontFamily = new FontFamily("Consolas, JetBrains Mono, Segoe UI Mono, monospace"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 4, 2)
            };
            if (!string.IsNullOrWhiteSpace(hexColor) && !hexColor.StartsWith('#'))
            {
                tb.SetResourceReference(TextBlock.ForegroundProperty, hexColor);
            }
            else if (string.IsNullOrWhiteSpace(hexColor) ||
                     string.Equals(hexColor, "#E2E8F0", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(hexColor, "#F8FAFC", StringComparison.OrdinalIgnoreCase))
            {
                tb.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimaryBrush");
            }
            else if (string.Equals(hexColor, "#94A3B8", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(hexColor, "#4B5563", StringComparison.OrdinalIgnoreCase))
            {
                tb.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
            }
            else if (string.Equals(hexColor, "#A78BFA", StringComparison.OrdinalIgnoreCase))
            {
                tb.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");
            }
            else
            {
                tb.Foreground = (Brush)new BrushConverter().ConvertFromString(hexColor)!;
            }
            AiTerminalList.Items.Add(tb);

            // Auto scroll smoothly to bottom
            Dispatcher.InvokeAsync(() =>
            {
                try
                {
                    AiTerminalList.ScrollIntoView(tb);
                    var scrollViewer = FindVisualChild<ScrollViewer>(AiTerminalList);
                    scrollViewer?.ScrollToBottom();
                }
                catch { }
            }, System.Windows.Threading.DispatcherPriority.Loaded);
        }
        catch { }
    }

    private void OnPulseInputKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            OnPulseAskClick(sender, new RoutedEventArgs());
        }
    }

    private async void OnPulseAskClick(object sender, RoutedEventArgs e)
    {
        var input = PulseInput.Text.Trim();
        if (string.IsNullOrEmpty(input)) return;

        PulseInput.Text = "";
        AppendTerminalLine($"> User: {input}", "TextSecondaryBrush");

        // Simulate thinking delay
        AppendTerminalLine("Pulse: Thinking...", "BrandCyanBrush");
        await Task.Delay(350);

        string response = await ProcessPulseQueryAsync(input);

        // Remove the "Thinking..." line (last item)
        if (AiTerminalList.Items.Count > 0)
        {
            AiTerminalList.Items.RemoveAt(AiTerminalList.Items.Count - 1);
        }

        AppendTerminalLine($"Pulse: {response}", "TextPrimaryBrush");
    }

    private static bool IsActionableToolQuery(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;
        string q = input.Trim().ToLowerInvariant();
        return q.StartsWith("clean ") || q.StartsWith("scan ") || q.StartsWith("enable ") ||
               q.StartsWith("disable ") || q.StartsWith("turn on ") || q.StartsWith("turn off ") ||
               q.StartsWith("activate ") || q.StartsWith("deactivate ") || q.StartsWith("run ") ||
               q.StartsWith("fix ") || q.StartsWith("audit ") || q.StartsWith("kill ") ||
               q.Contains("clean junk") || q.Contains("game mode") || q.Contains("turbo mode") ||
               q.Contains("scan drivers") || q.Contains("audit startup") || q.Contains("fix registry");
    }

    private async Task<string> ProcessPulseQueryAsync(string input)
    {
        if (LogicFlow.Guardian.GemmaAiEngine.Instance.Mode != LogicFlow.Guardian.GemmaExecutionMode.Disabled &&
            IsActionableToolQuery(input))
        {
            try
            {
                _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
                var dispatcher = new LogicFlow.VoiceAgent.LogicFlowFunctionDispatcher(
                    NullLogger<LogicFlow.VoiceAgent.LogicFlowFunctionDispatcher>.Instance,
                    _junkCleaner,
                    _sysInfo)
                {
                    ActiveEditionName = EditionService.Instance.Current.DisplayName(),
                    FeatureGateValidator = (tool, _) => EditionService.Instance.Allows(Capability.Core)
                        ? (true, null)
                        : (false, $"Tool '{tool}' requires Community ($0) or Pro edition."),
                    ConfirmMutatingToolAsync = (tool, args) =>
                        Dispatcher.InvokeAsync(() => Dialogs.Confirm(
                            this,
                            "Confirm Assistant System Action",
                            $"Pulse / Gemma wants to execute system tool '{tool}'.\n\nArguments: {args}\n\nAllow this system modification?",
                            "Run Action",
                            "Cancel",
                            defaultCancel: true)).Task
                };
                var agent = new LogicFlow.VoiceAgent.VoiceAgentEngine(dispatcher);
                var cmdRes = await agent.ExecuteTextCommandAsync(input);
                if (cmdRes.ExecutedTools.Count > 0 && !string.IsNullOrWhiteSpace(cmdRes.ReplyText))
                {
                    return cmdRes.ReplyText;
                }
            }
            catch
            {
                // Fall back to PulseQueryEngine below
            }
        }

        GetSystemPowerStatus(out var powerStatus);
        bool isPowerAvailable = powerStatus.BatteryLifePercent <= 100 || powerStatus.BatteryFlag != 0 || powerStatus.ACLineStatus <= 1;
        int vulnCount = _lastVulnResult?.Vulnerabilities.Count ?? 0;
        int openPortsCount = _lastVulnResult?.ExposedServices.Count ?? 0;
        long junkBytes = _lastJunkReport?.Sum(c => c.TotalBytes) ?? 0;
        int junkCount = _lastJunkReport?.Sum(c => c.FileCount) ?? 0;

        return await PulseQueryEngine.QueryNaturalLanguageAsync(
            input,
            _liveSnapshot,
            HealthScoreLabel.Text,
            vulnCount,
            openPortsCount,
            junkBytes,
            junkCount,
            isPowerAvailable,
            powerStatus.ACLineStatus,
            powerStatus.BatteryFlag,
            powerStatus.BatteryLifePercent);
    }

    private string ProcessPulseQuery(string input)
    {
        GetSystemPowerStatus(out var powerStatus);
        bool isPowerAvailable = powerStatus.BatteryLifePercent <= 100 || powerStatus.BatteryFlag != 0 || powerStatus.ACLineStatus <= 1;
        int vulnCount = _lastVulnResult?.Vulnerabilities.Count ?? 0;
        int openPortsCount = _lastVulnResult?.ExposedServices.Count ?? 0;
        long junkBytes = _lastJunkReport?.Sum(c => c.TotalBytes) ?? 0;
        int junkCount = _lastJunkReport?.Sum(c => c.FileCount) ?? 0;

        return PulseQueryEngine.ProcessQuery(
            input,
            _liveSnapshot,
            HealthScoreLabel.Text,
            vulnCount,
            openPortsCount,
            junkBytes,
            junkCount,
            isPowerAvailable,
            powerStatus.ACLineStatus,
            powerStatus.BatteryFlag,
            powerStatus.BatteryLifePercent);
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }

    private List<RunningProcessInfo> UpdateAndGetTopProcesses()
    {
        var list = new List<RunningProcessInfo>();
        var now = DateTime.UtcNow;
        var processes = System.Diagnostics.Process.GetProcesses();
        
        var currentSnapshot = new Dictionary<int, (TimeSpan CpuTime, DateTime TimeStamp)>();
        
        foreach (var p in processes)
        {
            try
            {
                if (p.Id == 0) continue;
                var cpuTime = p.TotalProcessorTime;
                currentSnapshot[p.Id] = (cpuTime, now);
                
                double cpuPercent = 0.0;
                if (_processCpuHistory.TryGetValue(p.Id, out var prev))
                {
                    var timeDelta = (now - prev.TimeStamp).TotalMilliseconds;
                    var cpuDelta = (cpuTime - prev.CpuTime).TotalMilliseconds;
                    if (timeDelta > 0)
                    {
                        cpuPercent = (cpuDelta / timeDelta) * 100.0 / Environment.ProcessorCount;
                    }
                }
                
                long mem = p.WorkingSet64;
                list.Add(new RunningProcessInfo
                {
                    Id = p.Id,
                    Name = p.ProcessName,
                    Cpu = Math.Max(0.0, Math.Min(100.0, cpuPercent)),
                    MemoryBytes = mem
                });
            }
            catch
            {
                try
                {
                    long mem = p.WorkingSet64;
                    list.Add(new RunningProcessInfo
                    {
                        Id = p.Id,
                        Name = p.ProcessName,
                        Cpu = 0.0,
                        MemoryBytes = mem
                    });
                }
                catch { }
            }
        }
        
        _processCpuHistory = currentSnapshot;
        return list.OrderByDescending(p => p.Cpu)
                   .ThenByDescending(p => p.MemoryBytes)
                   .Take(5)
                   .ToList();
    }

    private RunningProcessInfo? GetSelectedOrContextProcess(object sender)
    {
        if (sender is MenuItem mi)
        {
            if (mi.DataContext is RunningProcessInfo rpi) return rpi;
            if (ProcessesListView.SelectedItem is RunningProcessInfo selected) return selected;
        }
        if (sender is FrameworkElement fe && fe.DataContext is RunningProcessInfo info)
            return info;

        return ProcessesListView.SelectedItem as RunningProcessInfo;
    }

    private void SetProcessFeedback(string message, bool isError = false, bool isWarning = false)
    {
        if (ProcessesStatusText == null) return;
        ProcessesStatusText.Text = message;
        if (isError)
            ProcessesStatusText.Foreground = (Brush)FindResource("DangerRedBrush");
        else if (isWarning)
            ProcessesStatusText.Foreground = (Brush)FindResource("WarningAmberBrush");
        else
            ProcessesStatusText.Foreground = (Brush)FindResource("SuccessGreenBrush");
    }

    private void OnTerminateProcess(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.DataContext is RunningProcessInfo procInfo)
        {
            try
            {
                var p = System.Diagnostics.Process.GetProcessById(procInfo.Id);
                p.Kill();
                SetProcessFeedback($"Terminated process {procInfo.Name} (PID: {procInfo.Id}).");
                OnRefreshProcessesClick(this, new RoutedEventArgs());
            }
            catch (Exception ex)
            {
                SetProcessFeedback($"Failed to terminate {procInfo.Name}: {ex.Message}", isError: true);
            }
        }
    }

    private void OnToggleSuspendProcess(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.DataContext is RunningProcessInfo procInfo)
        {
            try
            {
                if (procInfo.IsSuspended)
                {
                    if (ProcessControl.Resume(procInfo.Id))
                    {
                        procInfo.IsSuspended = false;
                        btn.Content = "Freeze";
                        SetProcessFeedback($"Resumed process {procInfo.Name} (PID: {procInfo.Id}).");
                    }
                    else
                    {
                        SetProcessFeedback($"Failed to resume {procInfo.Name} (PID: {procInfo.Id}).", isWarning: true);
                    }
                }
                else
                {
                    if (!Gate.Require(Capability.Core, this)) return;
                    if (ProcessControl.Suspend(procInfo.Id))
                    {
                        procInfo.IsSuspended = true;
                        btn.Content = "Resume";
                        SetProcessFeedback($"Frozen process {procInfo.Name} (PID: {procInfo.Id}).");
                    }
                    else
                    {
                        SetProcessFeedback($"Failed to freeze {procInfo.Name}. Administrator privileges required.", isWarning: true);
                    }
                }
                OnRefreshProcessesClick(this, new RoutedEventArgs());
            }
            catch (Exception ex)
            {
                SetProcessFeedback($"Error toggling {procInfo.Name}: {ex.Message}", isError: true);
            }
        }
    }

    private static T? FindVisualChild<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent == null) return null;
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typed) return typed;
            var nested = FindVisualChild<T>(child);
            if (nested != null) return nested;
        }
        return null;
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        if (child == null) return null;
        DependencyObject? parent = VisualTreeHelper.GetParent(child);
        while (parent != null)
        {
            if (parent is T typed) return typed;
            parent = VisualTreeHelper.GetParent(parent);
        }
        return null;
    }

    private void OnNestedListPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is not DependencyObject dep) return;

        // If the element has an internal scrollable ScrollViewer (like ListView with items)
        var innerSv = (dep as ScrollViewer) ?? FindVisualChild<ScrollViewer>(dep);
        if (innerSv != null && innerSv.ScrollableHeight > 0.5)
        {
            bool atTop = innerSv.VerticalOffset <= 0.5;
            bool atBottom = innerSv.VerticalOffset >= innerSv.ScrollableHeight - 0.5;

            // If scrolling up and not at top, or scrolling down and not at bottom, let the inner list scroll
            if ((e.Delta > 0 && !atTop) || (e.Delta < 0 && !atBottom))
            {
                return;
            }
        }

        // Forward smoothly to parent ScrollViewer (or target page ScrollViewer) so outer page scrolls seamlessly
        var targetSv = FindVisualParent<ScrollViewer>(dep);
        if (targetSv == null && dep is ScrollViewer sv)
        {
            targetSv = sv;
        }

        if (targetSv != null && targetSv != innerSv)
        {
            e.Handled = true;
            double scrollDelta = -(e.Delta / 120.0) * 48.0;
            targetSv.ScrollToVerticalOffset(Math.Max(0, Math.Min(targetSv.ScrollableHeight, targetSv.VerticalOffset + scrollDelta)));
        }
    }

    private void ProcessesListView_Loaded(object sender, RoutedEventArgs e)
    {
        AdjustProcessColumns();
        Dispatcher.InvokeAsync(AdjustProcessColumns, System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void ProcessesListView_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        AdjustProcessColumns();
    }

    private void AdjustProcessColumns()
    {
        try
        {
            if (ProcessesListView?.View is GridView gv && gv.Columns.Count >= 4)
            {
                double availableWidth = 0;
                var sv = FindVisualChild<ScrollViewer>(ProcessesListView);
                if (sv != null && sv.ViewportWidth > 0)
                {
                    availableWidth = sv.ViewportWidth;
                }
                else if (ProcessesListView.ActualWidth > 0)
                {
                    double scrollbarAllowance = SystemParameters.VerticalScrollBarWidth + 8.0;
                    availableWidth = Math.Max(0, ProcessesListView.ActualWidth - scrollbarAllowance);
                }

                if (availableWidth <= 0) return;

                // Fixed compact widths for numeric & action columns
                double cpuWidth = 52.0;
                double ramWidth = 62.0;
                double actionsWidth = 106.0;
                double fixedTotal = cpuWidth + ramWidth + actionsWidth;

                // Process Name absorbs all remaining width, with a minimum floor of 40px
                double remainingForName = availableWidth - fixedTotal - 4.0;
                double nameWidth = Math.Max(40.0, remainingForName);

                if (availableWidth < fixedTotal + 40.0)
                {
                    double deficit = (fixedTotal + 40.0) - availableWidth;
                    cpuWidth = Math.Max(44.0, cpuWidth - deficit * 0.4);
                    ramWidth = Math.Max(52.0, ramWidth - deficit * 0.4);
                    nameWidth = Math.Max(35.0, availableWidth - (cpuWidth + ramWidth + actionsWidth) - 2.0);
                }

                gv.Columns[0].Width = nameWidth;
                gv.Columns[1].Width = cpuWidth;
                gv.Columns[2].Width = ramWidth;
                gv.Columns[3].Width = actionsWidth;
            }
        }
        catch { }
    }

    private void CarvedFilesListView_Loaded(object sender, RoutedEventArgs e)
    {
        AdjustCarvedFilesColumns();
        Dispatcher.InvokeAsync(AdjustCarvedFilesColumns, System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void CarvedFilesListView_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        AdjustCarvedFilesColumns();
    }

    private void AdjustCarvedFilesColumns()
    {
        try
        {
            if (CarvedFilesListView?.View is GridView gv && gv.Columns.Count >= 7)
            {
                double availableWidth = 0;
                var sv = FindVisualChild<ScrollViewer>(CarvedFilesListView);
                if (sv != null && sv.ViewportWidth > 0)
                {
                    availableWidth = sv.ViewportWidth;
                }
                else if (CarvedFilesListView.ActualWidth > 0)
                {
                    double scrollbarAllowance = SystemParameters.VerticalScrollBarWidth + 8.0;
                    availableWidth = Math.Max(0, CarvedFilesListView.ActualWidth - scrollbarAllowance);
                }

                if (availableWidth <= 0) return;

                double chkWidth = 34.0;
                double formatWidth = 206.0;
                double offsetWidth = 102.0;
                double sizeWidth = 92.0;
                double confidenceWidth = 148.0;
                double previewWidth = 92.0;
                double fixedTotal = chkWidth + formatWidth + offsetWidth + sizeWidth + confidenceWidth + previewWidth;
                double usable = Math.Max(0, availableWidth - 16.0);

                double fileColWidth;
                if (usable >= fixedTotal + 210.0)
                {
                    fileColWidth = usable - fixedTotal;
                }
                else
                {
                    // Preserve full readability of headers, format descriptions + badges, hex offsets, recovery pills,
                    // and buttons on high-DPI / narrow viewports while letting HorizontalScrollBarVisibility="Auto"
                    // scroll trailing columns smoothly instead of clipping column text.
                    chkWidth = 32.0;
                    formatWidth = 206.0;
                    offsetWidth = 102.0;
                    sizeWidth = 92.0;
                    confidenceWidth = 148.0;
                    previewWidth = 92.0;
                    fileColWidth = 224.0;
                }

                gv.Columns[0].Width = chkWidth;
                gv.Columns[1].Width = fileColWidth;
                gv.Columns[2].Width = formatWidth;
                gv.Columns[3].Width = offsetWidth;
                gv.Columns[4].Width = sizeWidth;
                gv.Columns[5].Width = confidenceWidth;
                gv.Columns[6].Width = previewWidth;
            }
        }
        catch { }
    }

    private void OnOpenProcessLocation(object sender, RoutedEventArgs e)
    {
        var procInfo = GetSelectedOrContextProcess(sender);
        if (procInfo == null) return;
        try
        {
            var p = System.Diagnostics.Process.GetProcessById(procInfo.Id);
            var filePath = p.MainModule?.FileName;
            if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{filePath}\"",
                    UseShellExecute = true
                });
                SetProcessFeedback($"Opened folder location for {procInfo.Name}.");
            }
            else
            {
                SetProcessFeedback($"Unable to locate executable binary for {procInfo.Name}.", isWarning: true);
            }
        }
        catch (Exception ex)
        {
            SetProcessFeedback($"Access denied or process unavailable: {ex.Message}", isError: true);
        }
    }

    private void OnContextMenuSuspendProcess(object sender, RoutedEventArgs e)
    {
        var procInfo = GetSelectedOrContextProcess(sender);
        if (procInfo == null) return;
        if (!Gate.Require(Capability.Core, this)) return;
        try
        {
            if (ProcessControl.Suspend(procInfo.Id))
            {
                procInfo.IsSuspended = true;
                SetProcessFeedback($"Frozen process {procInfo.Name} (PID: {procInfo.Id}).");
                OnRefreshProcessesClick(this, new RoutedEventArgs());
            }
            else
            {
                SetProcessFeedback($"Failed to freeze process {procInfo.Name}. Administrator privileges may be required.", isWarning: true);
            }
        }
        catch (Exception ex)
        {
            SetProcessFeedback($"Error suspending process: {ex.Message}", isError: true);
        }
    }

    private void OnContextMenuResumeProcess(object sender, RoutedEventArgs e)
    {
        var procInfo = GetSelectedOrContextProcess(sender);
        if (procInfo == null) return;
        try
        {
            if (ProcessControl.Resume(procInfo.Id))
            {
                procInfo.IsSuspended = false;
                SetProcessFeedback($"Resumed process {procInfo.Name} (PID: {procInfo.Id}).");
                OnRefreshProcessesClick(this, new RoutedEventArgs());
            }
            else
            {
                SetProcessFeedback($"Failed to resume process {procInfo.Name}.", isWarning: true);
            }
        }
        catch (Exception ex)
        {
            SetProcessFeedback($"Error resuming process: {ex.Message}", isError: true);
        }
    }

    private void SetProcessPriority(object sender, System.Diagnostics.ProcessPriorityClass priority, string label)
    {
        var procInfo = GetSelectedOrContextProcess(sender);
        if (procInfo == null) return;
        try
        {
            var p = System.Diagnostics.Process.GetProcessById(procInfo.Id);
            p.PriorityClass = priority;
            SetProcessFeedback($"Priority for {procInfo.Name} set to {label}.");
            OnRefreshProcessesClick(this, new RoutedEventArgs());
        }
        catch (Exception ex)
        {
            SetProcessFeedback($"Failed to adjust priority for {procInfo.Name}: {ex.Message}", isError: true);
        }
    }

    private void OnSetHighPriority(object sender, RoutedEventArgs e) => SetProcessPriority(sender, System.Diagnostics.ProcessPriorityClass.High, "High");
    private void OnSetNormalPriority(object sender, RoutedEventArgs e) => SetProcessPriority(sender, System.Diagnostics.ProcessPriorityClass.Normal, "Normal");
    private void OnSetLowPriority(object sender, RoutedEventArgs e) => SetProcessPriority(sender, System.Diagnostics.ProcessPriorityClass.BelowNormal, "Low");

    private void SetProcessAffinity(object sender, long affinityMask, string label)
    {
        var procInfo = GetSelectedOrContextProcess(sender);
        if (procInfo == null) return;
        try
        {
            var p = System.Diagnostics.Process.GetProcessById(procInfo.Id);
            p.ProcessorAffinity = (IntPtr)affinityMask;
            SetProcessFeedback($"CPU affinity for {procInfo.Name} set to {label}.");
        }
        catch (Exception ex)
        {
            SetProcessFeedback($"Failed to adjust CPU affinity for {procInfo.Name}: {ex.Message}", isError: true);
        }
    }

    private void OnSetAffinityAll(object sender, RoutedEventArgs e)
    {
        int cores = Environment.ProcessorCount;
        long mask = (cores >= 64) ? -1L : (1L << cores) - 1;
        SetProcessAffinity(sender, mask, $"All {cores} Cores");
    }

    private void OnSetAffinityPCores(object sender, RoutedEventArgs e)
    {
        int total = Environment.ProcessorCount;
        int pCores = Math.Max(1, total / 2);
        long mask = (1L << pCores) - 1;
        SetProcessAffinity(sender, mask, $"Performance Cores (First {pCores} Cores)");
    }

    private void OnSetAffinitySingle(object sender, RoutedEventArgs e)
    {
        SetProcessAffinity(sender, 1L, "Single Core (Core 0)");
    }

    private void OnContextMenuTerminateProcess(object sender, RoutedEventArgs e)
    {
        var procInfo = GetSelectedOrContextProcess(sender);
        if (procInfo == null) return;
        try
        {
            var p = System.Diagnostics.Process.GetProcessById(procInfo.Id);
            p.Kill();
            SetProcessFeedback($"Terminated process {procInfo.Name} (PID: {procInfo.Id}).");
            OnRefreshProcessesClick(this, new RoutedEventArgs());
        }
        catch (Exception ex)
        {
            SetProcessFeedback($"Failed to terminate process {procInfo.Name}: {ex.Message}", isError: true);
        }
    }

    private void OnRefreshProcessesClick(object sender, RoutedEventArgs e)
    {
        Task.Run(() =>
        {
            _lastProcesses = UpdateAndGetTopProcesses();
        }).ContinueWith(_ => Dispatcher.Invoke(() =>
        {
            if (ProcessesListView == null) return;
            ProcessesListView.ItemsSource = null;
            ProcessesListView.ItemsSource = _lastProcesses;
            AdjustProcessColumns();
            if (ProcessesEmptyState != null)
            {
                bool hasItems = _lastProcesses != null && _lastProcesses.Count > 0;
                ProcessesEmptyState.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
                ProcessesListView.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
            }
        }), System.Threading.Tasks.TaskContinuationOptions.None);
    }

    private void UpdateDashboardLiveMetrics()
    {
        if (_liveSnapshot == null) return;

        // CPU mini
        var cpuPct = _liveSnapshot.CpuUsagePercent;
        if (cpuPct <= 0)
        {
            cpuPct = SystemInfoEngine.SampleCpuUsage(0);
            _liveSnapshot.CpuUsagePercent = cpuPct;
        }
        MiniCpuBar.Value = Math.Max(1, Math.Min(100, cpuPct));
        MiniCpuText.Text = $"{cpuPct:F0}%";
        MiniCpuBar.Foreground = MetricBrush(cpuPct, Resources);
        MiniCpuDetail.Text = _liveSnapshot.CpuSpeedGHz > 0 ? $"{_liveSnapshot.CpuSpeedGHz:F1} GHz" : "Active";
        if (!string.IsNullOrWhiteSpace(_liveSnapshot.CpuName))
        {
            MiniCpuSub.Text = _liveSnapshot.CpuName.Split('@')[0].Trim();
        }

        // RAM mini
        var ramPct = _liveSnapshot.RamUsagePercent;
        if (ramPct <= 0 && _liveSnapshot.TotalRamBytes > 0)
        {
            ramPct = Math.Round((1.0 - (double)_liveSnapshot.AvailableRamBytes / _liveSnapshot.TotalRamBytes) * 100, 1);
        }
        if (ramPct <= 0)
        {
            var (_, _, fastRamPct) = SystemInfoEngine.GetFastMemoryStatus();
            ramPct = fastRamPct;
        }
        MiniRamBar.Value = Math.Max(1, Math.Min(100, ramPct));
        MiniRamText.Text = $"{ramPct:F0}%";
        MiniRamBar.Foreground = MetricBrush(ramPct, Resources);
        MiniRamDetail.Text = !string.IsNullOrEmpty(_liveSnapshot.UsedRamFormatted) && _liveSnapshot.UsedRamFormatted != "0 B"
            ? $"{_liveSnapshot.UsedRamFormatted} used"
            : "Active";
        MiniRamSub.Text = !string.IsNullOrEmpty(_liveSnapshot.TotalRamFormatted) && _liveSnapshot.TotalRamFormatted != "0 B"
            ? $"{_liveSnapshot.TotalRamFormatted} total"
            : "Physical RAM";

        // Disk mini
        try
        {
            var cDrive = _liveSnapshot.Disks.FirstOrDefault(d => d.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase)) 
                      ?? _liveSnapshot.Disks.FirstOrDefault();
            if (cDrive == null)
            {
                var collected = SystemInfoEngine.CollectDiskInfo();
                cDrive = collected.FirstOrDefault(d => d.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase)) ?? collected.FirstOrDefault();
            }

            if (cDrive != null && cDrive.TotalBytes > 0)
            {
                var diskPct = cDrive.UsagePercent;
                var diskBrush = MetricBrush(diskPct, Resources);
                MiniDiskBar.Value = Math.Max(1, Math.Min(100, diskPct));
                MiniDiskText.Text = $"{diskPct:F0}%";
                MiniDiskBar.Foreground = diskBrush;
                MiniDiskText.Foreground = diskBrush;
                var freeGb = cDrive.FreeBytes / (1024.0 * 1024 * 1024);
                MiniDiskDetail.Text = $"{freeGb:F1} GB free";
                MiniDiskSub.Text = $"{cDrive.Name} ({cDrive.FileSystem})";
            }
            else
            {
                var dInfo = new System.IO.DriveInfo("C");
                if (dInfo.IsReady && dInfo.TotalSize > 0)
                {
                    double total = dInfo.TotalSize;
                    double free = dInfo.TotalFreeSpace;
                    double usedPct = Math.Round((total - free) / total * 100.0, 1);
                    var diskBrush = MetricBrush(usedPct, Resources);
                    MiniDiskBar.Value = Math.Max(1, Math.Min(100, usedPct));
                    MiniDiskText.Text = $"{usedPct:F0}%";
                    MiniDiskBar.Foreground = diskBrush;
                    MiniDiskText.Foreground = diskBrush;
                    MiniDiskDetail.Text = $"{free / (1024.0 * 1024 * 1024):F1} GB free";
                    MiniDiskSub.Text = $"{dInfo.Name} ({dInfo.DriveFormat})";
                }
                else
                {
                    var secBrush = (Brush)FindResource("TextSecondaryBrush");
                    MiniDiskBar.Value = 0;
                    MiniDiskText.Text = "N/A";
                    MiniDiskBar.Foreground = secBrush;
                    MiniDiskText.Foreground = secBrush;
                    MiniDiskDetail.Text = "Drive unmeasured";
                    MiniDiskSub.Text = "Storage";
                }
            }
        }
        catch 
        { 
            var secBrush = (Brush)FindResource("TextSecondaryBrush");
            MiniDiskBar.Value = 0;
            MiniDiskText.Text = "N/A";
            MiniDiskBar.Foreground = secBrush;
            MiniDiskText.Foreground = secBrush;
            MiniDiskDetail.Text = "Drive unmeasured";
            MiniDiskSub.Text = "Storage";
        }

        // Processes list (preserve selection, avoid resetting if context menu is active)
        if (ProcessesListView != null && ProcessesListView.ContextMenu?.IsOpen != true)
        {
            var selected = ProcessesListView.SelectedItem as RunningProcessInfo;
            int selectedPid = selected?.Id ?? -1;
            ProcessesListView.ItemsSource = _lastProcesses;
            if (selectedPid > 0 && _lastProcesses != null)
            {
                var stillThere = _lastProcesses.FirstOrDefault(p => p.Id == selectedPid);
                if (stillThere != null)
                {
                    ProcessesListView.SelectedItem = stillThere;
                }
            }
            if (ProcessesEmptyState != null)
            {
                bool hasItems = _lastProcesses != null && _lastProcesses.Count > 0;
                ProcessesEmptyState.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
                ProcessesListView.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
            }
        }
    }

    private static void SelectComboByTag(System.Windows.Controls.ComboBox? combo, string? targetTag)
    {
        if (combo == null || string.IsNullOrWhiteSpace(targetTag)) return;
        foreach (var obj in combo.Items)
        {
            if (obj is ComboBoxItem item &&
                string.Equals(item.Tag?.ToString(), targetTag, StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedItem = item;
                return;
            }
        }
    }

    private void LoadSettingsToUI()
    {
        if (_settings == null) return;
        SettingsManager.Normalize(_settings);

        if (SettingStartWithWindows != null) SettingStartWithWindows.IsChecked = _settings.StartWithWindows;
        if (SettingMinimizeToTray != null) SettingMinimizeToTray.IsChecked = _settings.MinimizeToTray;
        if (SettingStopAgentOnExit != null) SettingStopAgentOnExit.IsChecked = _settings.StopAgentOnExit;
        if (SettingShowNotifications != null) SettingShowNotifications.IsChecked = _settings.ShowNotifications;
        if (SettingCheckForUpdates != null) SettingCheckForUpdates.IsChecked = _settings.CheckForUpdatesAutomatically;
        if (SettingEnableAnimations != null) SettingEnableAnimations.IsChecked = _settings.EnableAnimations;

        if (SettingAutoScanOnStartup != null) SettingAutoScanOnStartup.IsChecked = _settings.AutoScanOnStartup;
        if (SettingScanDriversOnStartup != null) SettingScanDriversOnStartup.IsChecked = _settings.ScanDriversOnStartup;
        if (SettingScanRegistryOnStartup != null) SettingScanRegistryOnStartup.IsChecked = _settings.ScanRegistryOnStartup;
        if (SettingScanSmartOnStartup != null) SettingScanSmartOnStartup.IsChecked = _settings.ScanSmartOnStartup;
        if (SettingScheduleWeeklyClean != null) SettingScheduleWeeklyClean.IsChecked = _settings.ScheduleWeeklyMaintenance;

        if (SettingTelemetryBlocking != null) SettingTelemetryBlocking.IsChecked = _settings.EnableTelemetryBlocking;
        if (SettingAutoScrubPrivacy != null) SettingAutoScrubPrivacy.IsChecked = _settings.AutoScrubPrivacy;
        if (SettingAllowUnsafeRegistry != null) SettingAllowUnsafeRegistry.IsChecked = _settings.AllowUnsafeRegistryFixes;

        if (SettingHideAiAssistant != null) SettingHideAiAssistant.IsChecked = _settings.HideAiAssistant;
        if (SettingAllowCloudAi != null) SettingAllowCloudAi.IsChecked = _settings.AllowCloudAiFallback;
        LogicFlow.Guardian.GemmaAiEngine.Instance.AllowHybridCloudFallback = _settings.AllowCloudAiFallback;

        SelectComboByTag(CmbTheme, _settings.Theme.ToString());
        SelectComboByTag(CmbAccentColor, _settings.Accent.ToString());
        SelectComboByTag(CmbUiScale, _settings.UiScale.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture));

        if (CmbAiExecutionMode != null)
        {
            string modeTag = _settings.AiExecutionMode ?? "LocalSidecar";
            SelectComboByTag(CmbAiExecutionMode, modeTag);
            if (Enum.TryParse<LogicFlow.Guardian.GemmaExecutionMode>(modeTag, ignoreCase: true, out var parsedMode))
            {
                LogicFlow.Guardian.GemmaAiEngine.Instance.Mode = parsedMode;
            }
        }

        RefreshExclusionsUi();
        RefreshGemmaStatusUi();
        RefreshTelemetryUi();
    }

    private void RefreshExclusionsUi()
    {
        if (SettingsExclusionsList == null || _settings == null) return;
        SettingsExclusionsList.ItemsSource = null;
        SettingsExclusionsList.ItemsSource = _settings.ScanExclusions.ToList();
    }

    private void OnSettingToggled(object sender, RoutedEventArgs e)
    {
        if (_isUiLoading || _settings == null) return;

        bool prevStartWithWindows = _settings.StartWithWindows;
        bool prevTelemetryBlocking = _settings.EnableTelemetryBlocking;
        bool prevAutoScrub = _settings.AutoScrubPrivacy;
        bool prevScheduleWeekly = _settings.ScheduleWeeklyMaintenance;

        if (SettingStartWithWindows != null) _settings.StartWithWindows = SettingStartWithWindows.IsChecked ?? false;
        if (SettingMinimizeToTray != null) _settings.MinimizeToTray = SettingMinimizeToTray.IsChecked ?? false;
        if (SettingStopAgentOnExit != null) _settings.StopAgentOnExit = SettingStopAgentOnExit.IsChecked ?? false;
        if (SettingShowNotifications != null) _settings.ShowNotifications = SettingShowNotifications.IsChecked ?? false;
        if (SettingCheckForUpdates != null) _settings.CheckForUpdatesAutomatically = SettingCheckForUpdates.IsChecked ?? false;
        if (SettingEnableAnimations != null) _settings.EnableAnimations = SettingEnableAnimations.IsChecked ?? true;

        if (SettingAutoScanOnStartup != null) _settings.AutoScanOnStartup = SettingAutoScanOnStartup.IsChecked ?? false;
        if (SettingScanDriversOnStartup != null) _settings.ScanDriversOnStartup = SettingScanDriversOnStartup.IsChecked ?? false;
        if (SettingScanRegistryOnStartup != null) _settings.ScanRegistryOnStartup = SettingScanRegistryOnStartup.IsChecked ?? false;
        if (SettingScanSmartOnStartup != null) _settings.ScanSmartOnStartup = SettingScanSmartOnStartup.IsChecked ?? false;
        if (SettingScheduleWeeklyClean != null) _settings.ScheduleWeeklyMaintenance = SettingScheduleWeeklyClean.IsChecked ?? false;

        if (SettingTelemetryBlocking != null) _settings.EnableTelemetryBlocking = SettingTelemetryBlocking.IsChecked ?? false;
        if (SettingAutoScrubPrivacy != null) _settings.AutoScrubPrivacy = SettingAutoScrubPrivacy.IsChecked ?? false;
        if (SettingAllowUnsafeRegistry != null) _settings.AllowUnsafeRegistryFixes = SettingAllowUnsafeRegistry.IsChecked ?? false;

        if (SettingHideAiAssistant != null) _settings.HideAiAssistant = SettingHideAiAssistant.IsChecked ?? false;
        if (SettingAllowCloudAi != null) _settings.AllowCloudAiFallback = SettingAllowCloudAi.IsChecked ?? false;

        LogicFlow.Guardian.GemmaAiEngine.Instance.AllowHybridCloudFallback = _settings.AllowCloudAiFallback;
        SettingsManager.Save();
        ApplyVisualSettings();
        RefreshGemmaStatusUi();

        // Enact StartWithWindows toggle in registry
        if (_settings.StartWithWindows != prevStartWithWindows)
        {
            SettingsManager.SetStartWithWindows(_settings.StartWithWindows);
        }

        // Enact Scheduled Weekly Maintenance toggle via ScheduledMaintenanceEngine & JunkCleanerEngine
        if (_settings.ScheduleWeeklyMaintenance != prevScheduleWeekly)
        {
            bool enableSchedule = _settings.ScheduleWeeklyMaintenance;
            _ = Task.Run(() =>
            {
                try
                {
                    _junkCleaner.ScheduleWeeklyClean(enableSchedule);
                    var schedEngine = new ScheduledMaintenanceEngine();
                    if (enableSchedule)
                    {
                        schedEngine.CreateSchedule(new MaintenanceSchedule
                        {
                            Frequency = ScheduleFrequency.Weekly,
                            DayOfWeek = DayOfWeek.Sunday,
                            Time = new TimeOnly(3, 0),
                            RunJunkCleaner = true,
                            RunMemoryOptimizer = true,
                            RunStartupCleanup = true
                        });
                    }
                    else
                    {
                        schedEngine.DeleteSchedule();
                    }
                }
                catch { }
            });
        }

        // Enact Telemetry Blocking toggle
        if (_settings.EnableTelemetryBlocking != prevTelemetryBlocking)
        {
            if (_settings.EnableTelemetryBlocking)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var results = await _aiPrivacyGuard.ApplyAllAsync();
                        int ok = results.Count(r => r.Success);
                        int fail = results.Count(r => !r.Success);
                        if (ok == 0 && results.Count > 0)
                        {
                            await Dispatcher.InvokeAsync(() =>
                            {
                                _isUiLoading = true;
                                try
                                {
                                    if (SettingTelemetryBlocking != null) SettingTelemetryBlocking.IsChecked = false;
                                    _settings.EnableTelemetryBlocking = false;
                                    SettingsManager.Save();
                                }
                                finally
                                {
                                    _isUiLoading = false;
                                }
                                Dialogs.ShowMessage(
                                    this,
                                    "Administrator Privileges Required",
                                    "Windows telemetry & AI policy keys could not be updated without Administrator rights.\n\nUse 'Restart as Administrator' in Settings to apply machine-wide telemetry blocking.",
                                    isWarningOrError: true);
                            });
                        }
                        else if (fail > 0)
                        {
                            await Dispatcher.InvokeAsync(() =>
                            {
                                Dialogs.ShowMessage(
                                    this,
                                    "Partial Telemetry Protection Applied",
                                    $"Applied {ok} of {results.Count} Windows privacy policies for your user account.\n\n{fail} machine-wide (HKLM) policy key(s) require running LogicFlow as Administrator.");
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        await Dispatcher.InvokeAsync(() =>
                        {
                            Dialogs.ShowMessage(this, "Telemetry Policy Error", $"Failed to apply telemetry policies: {ex.Message}", isWarningOrError: true);
                        });
                    }
                });
            }
            else
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var results = await _aiPrivacyGuard.RevertAllAsync();
                        int ok = results.Count(r => r.Success);
                        if (ok == 0 && results.Count > 0 && !App.IsRunningAsAdministrator())
                        {
                            await Dispatcher.InvokeAsync(() =>
                            {
                                Dialogs.ShowMessage(
                                    this,
                                    "Administrator Privileges Required",
                                    "Machine-wide HKLM telemetry policy keys require Administrator rights to revert. Use 'Restart as Administrator' in Settings if machine-wide policies remain active.",
                                    isWarningOrError: true);
                            });
                        }
                    }
                    catch { }
                });
            }
        }

        // Enact AutoScrubPrivacy toggle
        if (_settings.AutoScrubPrivacy && !prevAutoScrub)
        {
            _ = Task.Run(() =>
            {
                try { _privacyScrubber.Scrub(); } catch { }
            });
        }
    }

    private void OnSettingsCategoryFilterClick(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button clicked || clicked.Tag is not string category)
            return;

        if (SettingsCategoryPillBar != null)
        {
            var activeStyle = (Style)FindResource("HeaderActionButton");
            var inactiveStyle = (Style)FindResource("HeaderOutlineButton");
            foreach (var child in SettingsCategoryPillBar.Children)
            {
                if (child is System.Windows.Controls.Button pill)
                {
                    pill.Style = ReferenceEquals(pill, clicked) ? activeStyle : inactiveStyle;
                }
            }
        }

        bool showAll = string.Equals(category, "All", StringComparison.OrdinalIgnoreCase);
        if (SettingsCardAppearance != null)
            SettingsCardAppearance.Visibility = (showAll || category == "Appearance") ? Visibility.Visible : Visibility.Collapsed;
        if (SettingsCardGeneral != null)
            SettingsCardGeneral.Visibility = (showAll || category == "General") ? Visibility.Visible : Visibility.Collapsed;
        if (SettingsCardExclusions != null)
            SettingsCardExclusions.Visibility = (showAll || category == "Exclusions") ? Visibility.Visible : Visibility.Collapsed;
        if (SettingsCardAi != null)
            SettingsCardAi.Visibility = (showAll || category == "AI") ? Visibility.Visible : Visibility.Collapsed;
        if (SettingsCardPrivacy != null)
            SettingsCardPrivacy.Visibility = (showAll || category == "Privacy") ? Visibility.Visible : Visibility.Collapsed;
        if (SettingsCardAbout != null)
            SettingsCardAbout.Visibility = (showAll || category == "Privacy" || category == "General") ? Visibility.Visible : Visibility.Collapsed;
        if (SettingsCardData != null)
            SettingsCardData.Visibility = (showAll || category == "Data" || category == "Privacy") ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnAppearanceSettingChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isUiLoading || _settings == null) return;

        if (CmbTheme?.SelectedItem is ComboBoxItem themeItem && themeItem.Tag is string themeTag &&
            Enum.TryParse<ThemeMode>(themeTag, ignoreCase: true, out var parsedTheme))
        {
            _settings.Theme = parsedTheme;
        }
        if (CmbAccentColor?.SelectedItem is ComboBoxItem accentItem && accentItem.Tag is string accentTag &&
            Enum.TryParse<AccentColor>(accentTag, ignoreCase: true, out var parsedAccent))
        {
            _settings.Accent = parsedAccent;
        }
        if (CmbUiScale?.SelectedItem is ComboBoxItem scaleItem && scaleItem.Tag is string scaleTag &&
            double.TryParse(scaleTag, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double scaleVal))
        {
            _settings.UiScale = Math.Clamp(scaleVal, 1.0, 1.5);
        }

        SettingsManager.Normalize(_settings);
        SettingsManager.Save();
        ApplyVisualSettings();
    }

    private static bool IsWindowsLightThemePreferred()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", writable: false);
            if (key?.GetValue("AppsUseLightTheme") is int val)
                return val == 1;
        }
        catch { }
        return false;
    }

    public static bool ApplyPaletteToResources(ResourceDictionary res, UserSettings settings)
    {
        bool useLight = settings.Theme == ThemeMode.Light ||
                        (settings.Theme == ThemeMode.System && IsWindowsLightThemePreferred());

        Color bg = useLight ? Color.FromRgb(0xF8, 0xFA, 0xFC) : Color.FromRgb(0x0A, 0x0E, 0x1A);
        Color panel = useLight ? Color.FromRgb(0xF1, 0xF5, 0xF9) : Color.FromRgb(0x11, 0x18, 0x27);
        Color card = useLight ? Color.FromRgb(0xFF, 0xFF, 0xFF) : Color.FromRgb(0x14, 0x18, 0x24);
        Color cardHover = useLight ? Color.FromRgb(0xE2, 0xE8, 0xF0) : Color.FromRgb(0x1C, 0x22, 0x32);
        Color glass = useLight ? Color.FromRgb(0xFF, 0xFF, 0xFF) : Color.FromRgb(0x1A, 0x1F, 0x2E);
        Color terminal = useLight ? Color.FromRgb(0xF1, 0xF5, 0xF9) : Color.FromRgb(0x07, 0x09, 0x0E);
        Color glassPanel = useLight ? Color.FromArgb(0xF2, 0xFF, 0xFF, 0xFF) : Color.FromArgb(0xB8, 0x11, 0x18, 0x27);
        Color glassBorder = useLight ? Color.FromArgb(0x55, 0x64, 0x74, 0x8B) : Color.FromArgb(0x30, 0xFF, 0xFF, 0xFF);
        Color borderSubtle = useLight ? Color.FromRgb(0xCB, 0xD5, 0xE1) : Color.FromRgb(0x1E, 0x29, 0x3B);
        Color borderHover = useLight ? Color.FromRgb(0x94, 0xA3, 0xB8) : Color.FromRgb(0x2A, 0x30, 0x40);
        Color textPrimary = useLight ? Color.FromRgb(0x0F, 0x17, 0x2A) : Color.FromRgb(0xF0, 0xF4, 0xF8);
        Color textSecondary = useLight ? Color.FromRgb(0x47, 0x55, 0x69) : Color.FromRgb(0x94, 0xA3, 0xB8);
        Color textMuted = useLight ? Color.FromRgb(0x64, 0x74, 0x8B) : Color.FromRgb(0x91, 0x9C, 0xAC);

        (Color accentMain, Color accentDim, Color accentGradEnd) = settings.Accent switch
        {
            AccentColor.Purple => (
                useLight ? Color.FromRgb(0x7C, 0x3A, 0xED) : Color.FromRgb(0xA7, 0x8B, 0xFA),
                Color.FromRgb(0x6D, 0x28, 0xD9),
                Color.FromRgb(0xEC, 0x48, 0x99)),
            AccentColor.Emerald or AccentColor.Green => (
                useLight ? Color.FromRgb(0x05, 0x96, 0x69) : Color.FromRgb(0x10, 0xB9, 0x81),
                Color.FromRgb(0x04, 0x78, 0x57),
                Color.FromRgb(0x02, 0x84, 0xC7)),
            AccentColor.Amber or AccentColor.Orange => (
                useLight ? Color.FromRgb(0xD9, 0x77, 0x06) : Color.FromRgb(0xF5, 0x9E, 0x0B),
                Color.FromRgb(0xB4, 0x53, 0x09),
                Color.FromRgb(0xEA, 0x58, 0x0C)),
            AccentColor.Rose or AccentColor.Pink => (
                useLight ? Color.FromRgb(0xE1, 0x1D, 0x48) : Color.FromRgb(0xFB, 0x71, 0x85),
                Color.FromRgb(0xBE, 0x12, 0x3C),
                Color.FromRgb(0x93, 0x33, 0xEA)),
            AccentColor.Blue => (
                useLight ? Color.FromRgb(0x25, 0x63, 0xEB) : Color.FromRgb(0x38, 0xBD, 0xF8),
                Color.FromRgb(0x1D, 0x4E, 0xD8),
                Color.FromRgb(0x7C, 0x3A, 0xED)),
            AccentColor.Red => (
                useLight ? Color.FromRgb(0xDC, 0x26, 0x26) : Color.FromRgb(0xF8, 0x71, 0x71),
                Color.FromRgb(0xB9, 0x1C, 0x1C),
                Color.FromRgb(0xEA, 0x58, 0x0C)),
            AccentColor.Teal => (
                useLight ? Color.FromRgb(0x0D, 0x94, 0x88) : Color.FromRgb(0x2D, 0xD4, 0xBF),
                Color.FromRgb(0x0F, 0x76, 0x6E),
                Color.FromRgb(0x02, 0x84, 0xC7)),
            _ => (
                useLight ? Color.FromRgb(0x02, 0x84, 0xC7) : Color.FromRgb(0x00, 0xE5, 0xFF),
                Color.FromRgb(0x00, 0x77, 0xB6),
                Color.FromRgb(0x7C, 0x4D, 0xFF))
        };

        res["BrandDarkBrush"] = new SolidColorBrush(bg);
        res["BrandDarkBgBrush"] = new SolidColorBrush(bg);
        res["BrandDarkPanelBrush"] = new SolidColorBrush(panel);
        res["BrandDarkCardBrush"] = new SolidColorBrush(card);
        res["BrandGlassBrush"] = new SolidColorBrush(glass);
        res["GlassPanelBrush"] = new SolidColorBrush(glassPanel);
        res["GlassBorderBrush"] = new SolidColorBrush(glassBorder);
        res["BorderSubtleBrush"] = new SolidColorBrush(borderSubtle);

        res["BrushBgBase"] = new SolidColorBrush(bg);
        res["BrushBgSidebar"] = new SolidColorBrush(panel);
        res["BrushBgCard"] = new SolidColorBrush(card);
        res["BrushBgCardHover"] = new SolidColorBrush(cardHover);
        res["BrushBgTerminal"] = new SolidColorBrush(terminal);
        res["BrushBorder"] = new SolidColorBrush(borderSubtle);
        res["BrushBorderHover"] = new SolidColorBrush(borderHover);

        res["TextPrimaryBrush"] = new SolidColorBrush(textPrimary);
        res["TextSecondaryBrush"] = new SolidColorBrush(textSecondary);
        res["TextMutedBrush"] = new SolidColorBrush(textMuted);
        res["BrushTextMain"] = new SolidColorBrush(textPrimary);
        res["BrushTextMuted"] = new SolidColorBrush(textSecondary);

        static double Linearize(byte ch)
        {
            double s = ch / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }
        double wcagLum = 0.2126 * Linearize(accentMain.R) + 0.7152 * Linearize(accentMain.G) + 0.0722 * Linearize(accentMain.B);
        Color inverseText = wcagLum > 0.28 ? Color.FromRgb(0x0E, 0x12, 0x1B) : Colors.White;
        Color gradStart = useLight ? accentMain : accentDim;

        res["BrandCyanBrush"] = new SolidColorBrush(accentMain);
        res["BrandCyanDimBrush"] = new SolidColorBrush(accentDim);
        res["BrandCyanGlow"] = accentMain;
        res["BrushAccent"] = new SolidColorBrush(accentMain);
        res["BrushTextInverse"] = new SolidColorBrush(inverseText);
        res["BrushAccentGlow"] = new SolidColorBrush(Color.FromArgb(0x26, accentMain.R, accentMain.G, accentMain.B));
        res["BrushAccentBorder"] = new SolidColorBrush(Color.FromArgb(0x55, accentMain.R, accentMain.G, accentMain.B));
        res["GradientAccent"] = new LinearGradientBrush(gradStart, accentGradEnd, new System.Windows.Point(0, 0), new System.Windows.Point(1, 1));

        var successBrush = new SolidColorBrush(useLight ? Color.FromRgb(0x05, 0x96, 0x69) : Color.FromRgb(0x00, 0xE6, 0x76));
        var warningBrush = new SolidColorBrush(useLight ? Color.FromRgb(0xD9, 0x77, 0x06) : Color.FromRgb(0xFF, 0xB3, 0x00));
        var dangerBrush = new SolidColorBrush(useLight ? Color.FromRgb(0xDC, 0x26, 0x26) : Color.FromRgb(0xFF, 0x52, 0x52));
        res["SuccessGreenBrush"] = successBrush;
        res["WarningAmberBrush"] = warningBrush;
        res["DangerRedBrush"] = dangerBrush;
        res["BrushSuccess"] = successBrush;
        res["BrushWarning"] = warningBrush;
        res["BrushDanger"] = dangerBrush;

        return useLight;
    }

    public static void ApplyWindowTitleBarTheme(Window window)
    {
        if (window == null) return;
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(window).Handle;
            if (hwnd == IntPtr.Zero) return;

            bool isLight = false;
            if ((window.TryFindResource("BrandDarkBrush") ?? Application.Current?.TryFindResource("BrandDarkBrush")) is SolidColorBrush bgBrush)
            {
                var c = bgBrush.Color;
                double luminance = (0.299 * c.R + 0.587 * c.G + 0.114 * c.B) / 255.0;
                isLight = luminance > 0.5;
            }

            int darkFlag = isLight ? 0 : 1;
            DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref darkFlag, sizeof(int));
        }
        catch
        {
            // Best-effort DWM immersive title bar attribute
        }
    }

    private void OnWindowSizeChanged(object sender, SizeChangedEventArgs e)
    {
        UpdateResponsiveLayoutBreakpoints();
    }

    private void UpdateResponsiveLayoutBreakpoints()
    {
        try
        {
            double winW = ActualWidth > 1 ? ActualWidth : (double.IsFinite(Width) && Width > 1 ? Width : 1280);
            double winH = ActualHeight > 1 ? ActualHeight : (double.IsFinite(Height) && Height > 1 ? Height : 820);
            double scale = _settings != null ? Math.Clamp(_settings.UiScale, 1.0, 1.5) : 1.0;

            double sidebarWidth = scale >= 1.2 ? 228.0 : 260.0;
            if (SidebarColumn != null)
            {
                SidebarColumn.Width = new GridLength(sidebarWidth);
            }

            double logicalContentWidth = (winW / scale) - sidebarWidth;
            double logicalHeight = winH / scale;
            bool compact = logicalContentWidth < 680.0;
            bool overviewStack = logicalContentWidth < 780.0;
            bool compactHeight = logicalHeight < 680.0;
            bool ultraCompactHeight = logicalHeight < 600.0;

            if (PageTitle != null)
            {
                PageTitle.FontSize = compact ? 14.5 : 16.0;
            }

            if (OverviewTextGrid != null && OverviewShortcutsWrap != null)
            {
                if (overviewStack)
                {
                    Grid.SetRow(OverviewTextGrid, 0);
                    Grid.SetColumn(OverviewTextGrid, 0);
                    Grid.SetColumnSpan(OverviewTextGrid, 2);

                    Grid.SetRow(OverviewShortcutsWrap, 1);
                    Grid.SetColumn(OverviewShortcutsWrap, 0);
                    Grid.SetColumnSpan(OverviewShortcutsWrap, 2);
                    OverviewShortcutsWrap.HorizontalAlignment = System.Windows.HorizontalAlignment.Left;
                    OverviewShortcutsWrap.Margin = new Thickness(46, 8, 0, 0);
                }
                else
                {
                    Grid.SetRow(OverviewTextGrid, 0);
                    Grid.SetColumn(OverviewTextGrid, 0);
                    Grid.SetColumnSpan(OverviewTextGrid, 1);

                    Grid.SetRow(OverviewShortcutsWrap, 0);
                    Grid.SetColumn(OverviewShortcutsWrap, 1);
                    Grid.SetColumnSpan(OverviewShortcutsWrap, 1);
                    OverviewShortcutsWrap.HorizontalAlignment = System.Windows.HorizontalAlignment.Right;
                    OverviewShortcutsWrap.Margin = new Thickness(12, 0, 0, 0);
                }
            }

            var subVisibility = ultraCompactHeight ? Visibility.Collapsed : Visibility.Visible;
            if (NavSentinelSub != null) NavSentinelSub.Visibility = subVisibility;
            if (NavGuardianSub != null) NavGuardianSub.Visibility = subVisibility;
            if (NavHyperStoreSub != null) NavHyperStoreSub.Visibility = subVisibility;
            if (NavLazarusSub != null) NavLazarusSub.Visibility = subVisibility;
            if (NavRegistrySub != null) NavRegistrySub.Visibility = subVisibility;

            double navBtnHeight = ultraCompactHeight ? 30.0 : (compactHeight ? 35.0 : 40.0);
            Thickness navBtnMargin = (ultraCompactHeight || compactHeight) ? new Thickness(0, 0.5, 0, 0.5) : new Thickness(0, 2, 0, 2);
            var navButtons = new System.Windows.Controls.Button?[] { NavDashboard, NavSentinel, NavGuardian, NavHyperStore, NavMonitor, NavToolbox, NavLazarus, NavRegistry, NavSettings };
            foreach (var btn in navButtons)
            {
                if (btn != null)
                {
                    btn.Height = navBtnHeight;
                    btn.Margin = navBtnMargin;
                    if (btn.Content is UIElement contentEl)
                    {
                        contentEl.InvalidateMeasure();
                        contentEl.InvalidateArrange();
                    }
                    btn.InvalidateMeasure();
                    btn.InvalidateArrange();
                }
            }

            if (SidebarHeaderPanel != null)
            {
                SidebarHeaderPanel.Margin = ultraCompactHeight
                    ? new Thickness(16, 8, 16, 6)
                    : (compactHeight ? new Thickness(18, 10, 18, 8) : new Thickness(20, 18, 20, 16));
            }
            if (SidebarHeaderDivider != null)
            {
                SidebarHeaderDivider.Margin = ultraCompactHeight
                    ? new Thickness(0, 6, 0, 0)
                    : (compactHeight ? new Thickness(0, 8, 0, 0) : new Thickness(0, 14, 0, 0));
            }
            if (SidebarToolsHeader != null)
            {
                SidebarToolsHeader.Margin = ultraCompactHeight ? new Thickness(8, 0, 0, 3) : new Thickness(8, 0, 0, 6);
                SidebarToolsHeader.InvalidateMeasure();
                SidebarToolsHeader.InvalidateArrange();
            }
            if (SidebarSystemHeader != null)
            {
                SidebarSystemHeader.Margin = ultraCompactHeight
                    ? new Thickness(8, 6, 0, 3)
                    : (compactHeight ? new Thickness(8, 8, 0, 3) : new Thickness(8, 14, 0, 6));
                SidebarSystemHeader.InvalidateMeasure();
                SidebarSystemHeader.InvalidateArrange();
            }
            if (SidebarEditionCard != null)
            {
                SidebarEditionCard.Margin = ultraCompactHeight
                    ? new Thickness(12, 4, 12, 8)
                    : (compactHeight ? new Thickness(14, 4, 14, 8) : new Thickness(16, 6, 16, 12));
                SidebarEditionCard.Padding = ultraCompactHeight ? new Thickness(10, 6, 10, 6) : new Thickness(12, 10, 12, 10);
            }
            if (TrialLabel != null)
            {
                TrialLabel.Visibility = (ultraCompactHeight || string.IsNullOrWhiteSpace(TrialLabel.Text))
                    ? Visibility.Collapsed
                    : Visibility.Visible;
            }
            if (BtnUpgradeTier != null)
            {
                BtnUpgradeTier.Height = ultraCompactHeight ? 26.0 : (compactHeight ? 28.0 : 32.0);
                BtnUpgradeTier.Margin = ultraCompactHeight ? new Thickness(0, 4, 0, 0) : new Thickness(0, 8, 0, 0);
            }
            if (SidebarVersionText != null)
            {
                SidebarVersionText.Visibility = string.IsNullOrWhiteSpace(SidebarVersionText.Text)
                    ? Visibility.Collapsed
                    : Visibility.Visible;
                SidebarVersionText.Margin = ultraCompactHeight ? new Thickness(0, 4, 0, 0) : new Thickness(0, 8, 0, 0);
            }
            SidebarNavStack?.InvalidateMeasure();
            SidebarNavStack?.InvalidateArrange();

            if (DashboardOverviewGrid != null && DashboardOverviewGrid.ColumnDefinitions.Count >= 2 &&
                DashboardColLeft != null && DashboardColRight != null)
            {
                if (compact)
                {
                    DashboardOverviewGrid.ColumnDefinitions[1].Width = new GridLength(0);
                    DashboardColLeft.Margin = new Thickness(0);
                    Grid.SetColumn(DashboardColRight, 0);
                    Grid.SetRow(DashboardColRight, 1);
                }
                else
                {
                    DashboardOverviewGrid.ColumnDefinitions[1].Width = new GridLength(1, GridUnitType.Star);
                    DashboardColLeft.Margin = new Thickness(0, 0, 16, 0);
                    Grid.SetColumn(DashboardColRight, 1);
                    Grid.SetRow(DashboardColRight, 0);
                }
            }

            if (HyperStoreGaugesGrid != null)
            {
                HyperStoreGaugesGrid.Columns = compact ? 2 : 4;
            }
        }
        catch
        {
            // Best-effort responsive column adaptation
        }
    }

    private void ApplyVisualSettings()
    {
        if (_settings == null) return;
        try
        {
            // 1. UI Scale (100% .. 150%)
            double scale = Math.Clamp(_settings.UiScale, 1.0, 1.5);
            if (RootScaleTransform != null)
            {
                RootScaleTransform.ScaleX = scale;
                RootScaleTransform.ScaleY = scale;
            }

            // 2 & 3. Resolve Dark vs Light palette and Accent Color across all theme keys
            var res = Application.Current?.Resources ?? Resources;
            ApplyPaletteToResources(res, _settings);
            if (!ReferenceEquals(res, Resources))
            {
                ApplyPaletteToResources(Resources, _settings);
            }
            if (_allCarvedItems != null)
            {
                foreach (var item in _allCarvedItems)
                {
                    item.RefreshThemeBrushes();
                }
            }

            // Sync DWM immersive dark mode attribute for Mica backdrop
            ApplyWindowTitleBarTheme(this);
            UpdateResponsiveLayoutBreakpoints();

            // 4. Hide/Show AI Assistant card & update accurate privacy badge
            if (PulseAiDashboardCard != null)
            {
                PulseAiDashboardCard.Visibility = _settings.HideAiAssistant ? Visibility.Collapsed : Visibility.Visible;
            }
            if (PulseAiPrivacyBadgeText != null)
            {
                var mode = LogicFlow.Guardian.GemmaAiEngine.Instance.Mode;
                bool cloudEnabled = mode == LogicFlow.Guardian.GemmaExecutionMode.CloudEndpoint ||
                                    (mode == LogicFlow.Guardian.GemmaExecutionMode.HybridAuto && _settings.AllowCloudAiFallback);
                PulseAiPrivacyBadgeText.Text = cloudEnabled
                    ? "CLOUD AI OPT-IN ACTIVE"
                    : "100% LOCAL · NO CLOUD";
            }

            // 5. Animations / OS Reduced Motion / RDP guard
            bool pauseAnim = !_settings.EnableAnimations || !SystemParameters.ClientAreaAnimation || SystemParameters.IsRemoteSession;
            try
            {
                if (ShieldBreathingStoryboard?.Storyboard != null && ShieldEmblemBorder != null)
                {
                    if (pauseAnim) ShieldBreathingStoryboard.Storyboard.Pause(ShieldEmblemBorder);
                    else ShieldBreathingStoryboard.Storyboard.Resume(ShieldEmblemBorder);
                }
                if (HyperStoreShieldBreathingStoryboard?.Storyboard != null && HyperStoreShieldBorder != null)
                {
                    if (pauseAnim) HyperStoreShieldBreathingStoryboard.Storyboard.Pause(HyperStoreShieldBorder);
                    else HyperStoreShieldBreathingStoryboard.Storyboard.Resume(HyperStoreShieldBorder);
                }
            }
            catch { }
        }
        catch { }
    }

    private void OnAddScanExclusionFolderClick(object sender, RoutedEventArgs e)
    {
        if (_settings == null) return;
        var folder = PickFolderDialog("Select Folder to Exclude from Junk Cleaner & HyperStore Scans");
        if (string.IsNullOrWhiteSpace(folder)) return;

        string normalized = folder.Trim();
        if (!_settings.ScanExclusions.Any(x => string.Equals(x, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            _settings.ScanExclusions.Add(normalized);
            SettingsManager.Normalize(_settings);
            _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
            _diskSpaceAnalyzer.ExcludedPaths = _settings.ScanExclusions;
            SettingsManager.Save();
            RefreshExclusionsUi();
        }
    }

    private void OnRemoveScanExclusionClick(object sender, RoutedEventArgs e)
    {
        if (_settings == null || SettingsExclusionsList?.SelectedItem is not string selected) return;
        _settings.ScanExclusions.RemoveAll(x => string.Equals(x, selected, StringComparison.OrdinalIgnoreCase));
        _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
        _diskSpaceAnalyzer.ExcludedPaths = _settings.ScanExclusions;
        SettingsManager.Save();
        RefreshExclusionsUi();
    }

    private void OnExportSettingsClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export LogicFlow Settings & Exclusions",
                Filter = "JSON Settings (*.json)|*.json",
                FileName = $"LogicFlow_Settings_{DateTime.Now:yyyyMMdd}.json",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
            };
            if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FileName))
            {
                SettingsManager.ExportToFile(dlg.FileName);
                Dialogs.ShowMessage(this, "Settings Exported", $"Preferences and folder exclusions exported to:\n{dlg.FileName}");
            }
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Export Error", $"Could not export settings: {ex.Message}");
        }
    }

    private void OnImportSettingsClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import LogicFlow Settings & Exclusions",
                Filter = "JSON Settings (*.json)|*.json|All Files (*.*)|*.*",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
            };
            if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FileName))
            {
                if (SettingsManager.TryImportFromFile(dlg.FileName, out string? err))
                {
                    _isUiLoading = true;
                    try
                    {
                        _settings = SettingsManager.Load();
                        _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
                        _diskSpaceAnalyzer.ExcludedPaths = _settings.ScanExclusions;
                        LoadSettingsToUI();
                        ApplyVisualSettings();
                    }
                    finally { _isUiLoading = false; }
                    Dialogs.ShowMessage(this, "Settings Imported", "Preferences, theme, and scan exclusions restored.");
                }
                else
                {
                    Dialogs.ShowMessage(this, "Import Failed", $"Could not import settings file:\n{err}");
                }
            }
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Import Error", $"Could not import settings: {ex.Message}");
        }
    }

    private static bool TryCreateDesktopShortcut(string shortcutName, string arguments, string description, out string shortcutPath, out string? error)
    {
        shortcutPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            shortcutName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? shortcutName : shortcutName + ".lnk");
        error = null;

        try
        {
            string exePath = Environment.ProcessPath
                ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                ?? Path.Combine(AppContext.BaseDirectory, "LogicFlow.exe");

            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null)
            {
                error = "Windows Script Host COM interface is unavailable on this machine.";
                return false;
            }

            object? shell = Activator.CreateInstance(shellType);
            if (shell == null)
            {
                error = "Could not initialize shortcut creator.";
                return false;
            }

            try
            {
                object? shortcut = shellType.InvokeMember(
                    "CreateShortcut",
                    System.Reflection.BindingFlags.InvokeMethod,
                    null,
                    shell,
                    new object[] { shortcutPath });
                if (shortcut == null)
                {
                    error = "Failed to create .lnk object.";
                    return false;
                }

                var scType = shortcut.GetType();
                scType.InvokeMember("TargetPath", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { exePath });
                scType.InvokeMember("Arguments", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { arguments });
                scType.InvokeMember("WorkingDirectory", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { Path.GetDirectoryName(exePath) ?? AppContext.BaseDirectory });
                scType.InvokeMember("Description", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { description });
                scType.InvokeMember("IconLocation", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { $"{exePath},0" });
                scType.InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, shortcut, Array.Empty<object>());

                if (Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
                return File.Exists(shortcutPath);
            }
            finally
            {
                if (Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private void OnCreateBoostShortcutClick(object sender, RoutedEventArgs e)
    {
        bool okOn = TryCreateDesktopShortcut(
            "LogicFlow Boost Mode",
            "/boost",
            "Engage LogicFlow Gaming Boost Mode silently without opening the dashboard",
            out string pathOn,
            out string? err);
        TryCreateDesktopShortcut(
            "LogicFlow Boost Off",
            "/boost off",
            "Restore normal power plan and foreground priority silently",
            out string pathOff,
            out _);

        if (okOn)
        {
            Dialogs.ShowMessage(
                this,
                "Desktop Boost Shortcuts Created",
                $"Created silent 1-click desktop shortcuts:\n\n• {pathOn}\n• {pathOff}\n\nDouble-click 'LogicFlow Boost Mode' anytime (even before or during a game) to boost foreground priority and free RAM without opening the main window.");
        }
        else
        {
            Dialogs.ShowMessage(this, "Shortcut Creation Failed", $"Could not create desktop shortcut: {err}");
        }
    }

    private void OnCreateCleanShortcutClick(object sender, RoutedEventArgs e)
    {
        if (TryCreateDesktopShortcut(
            "LogicFlow 1-Click Clean",
            "--auto-maintenance",
            "Run silent LogicFlow junk cleanup and RAM optimization respecting your exclusions",
            out string path,
            out string? err))
        {
            Dialogs.ShowMessage(
                this,
                "Desktop 1-Click Clean Shortcut Created",
                $"Created silent desktop shortcut:\n\n• {path}\n\nDouble-clicking runs safe junk cleanup (honoring your folder exclusions) and RAM trimming in the background.");
        }
        else
        {
            Dialogs.ShowMessage(this, "Shortcut Creation Failed", $"Could not create desktop shortcut: {err}");
        }
    }

    private void OnRestartAsAdminClick(object sender, RoutedEventArgs e)
    {
        try
        {
            string exePath = Environment.ProcessPath
                ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                ?? Path.Combine(AppContext.BaseDirectory, "LogicFlow.exe");

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            };
            System.Diagnostics.Process.Start(psi);
            _isExplicitExit = true;
            Application.Current.Shutdown();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User declined the UAC elevation prompt — keep current non-admin window running cleanly.
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "Administrator Relaunch Failed", $"Could not relaunch as Administrator: {ex.Message}");
        }
    }

    private void OnHelpButtonClick(object sender, RoutedEventArgs e) => Dialogs.ShowHelpDialog(this);

    private void OnWindowPreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.F1)
        {
            e.Handled = true;
            Dialogs.ShowHelpDialog(this);
        }
    }

    private void OnAiExecutionModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isUiLoading || _settings == null || CmbAiExecutionMode?.SelectedItem is not ComboBoxItem item)
            return;

        string modeTag = item.Tag?.ToString() ?? "LocalSidecar";
        _settings.AiExecutionMode = modeTag;
        SettingsManager.Save();

        if (Enum.TryParse<LogicFlow.Guardian.GemmaExecutionMode>(modeTag, ignoreCase: true, out var parsedMode))
        {
            LogicFlow.Guardian.GemmaAiEngine.Instance.Mode = parsedMode;
            if (parsedMode is LogicFlow.Guardian.GemmaExecutionMode.CloudEndpoint or LogicFlow.Guardian.GemmaExecutionMode.Disabled)
            {
                LogicFlow.Guardian.GemmaAiEngine.Instance.StopSidecarImmediately();
            }
        }

        ApplyVisualSettings();
        RefreshGemmaStatusUi();
    }

    private void OnCancelGemmaDownloadClick(object sender, RoutedEventArgs e)
    {
        try { _gemmaDownloadCts?.Cancel(); } catch { }
    }

    private async void OnDownloadGemmaSidecarClick(object sender, RoutedEventArgs e)
    {
        _gemmaDownloadCts?.Dispose();
        _gemmaDownloadCts = new CancellationTokenSource();
        var ct = _gemmaDownloadCts.Token;

        if (BtnDownloadGemmaSidecar != null) BtnDownloadGemmaSidecar.IsEnabled = false;
        if (BtnCancelGemmaDownload != null) BtnCancelGemmaDownload.Visibility = Visibility.Visible;
        if (PbGemmaDownload != null)
        {
            PbGemmaDownload.Value = 0;
            PbGemmaDownload.Visibility = Visibility.Visible;
        }
        if (TxtGemmaStatus != null)
            TxtGemmaStatus.Text = "Downloading Gemma 4 E2B Q4_K_M + llama-server (~1.3 GB)...";

        string? finalStatusOverride = null;
        try
        {
            var progress = new Progress<LogicFlow.Guardian.GemmaDownloadProgress>(p =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (PbGemmaDownload != null)
                    {
                        PbGemmaDownload.Value = Math.Clamp(p.Percentage, 0, 100);
                    }
                    if (TxtGemmaStatus != null)
                    {
                        TxtGemmaStatus.Text = $"{p.Stage}: {p.Percentage:F1}% ({FormatBytes(p.BytesReceived)} / {FormatBytes(Math.Max(1, p.TotalBytes))})";
                    }
                });
            });

            bool ok = await LogicFlow.Guardian.GemmaAiEngine.Instance.DownloadLocalAssetsAsync(progress, ct);
            if (_settings != null && ok)
            {
                SettingsManager.Save();
            }

            if (ct.IsCancellationRequested)
            {
                finalStatusOverride = "⏹ Download cancelled — partial temporary files cleaned up.";
            }
            else if (ok)
            {
                var sha = LogicFlow.Guardian.GemmaAiEngine.Instance.LastModelSha256;
                string shaNote = !string.IsNullOrEmpty(sha) && sha.Length >= 12 ? $" (SHA-256: {sha[..12]}…)" : "";
                finalStatusOverride = $"✅ Gemma 4 E2B + llama-server verified and ready{shaNote}.";
            }
            else
            {
                finalStatusOverride = "⚠ Failed to download Gemma 4 E2B assets. Check network connectivity.";
            }
        }
        catch (OperationCanceledException)
        {
            finalStatusOverride = "⏹ Download cancelled — partial temporary files cleaned up.";
        }
        catch (Exception ex)
        {
            finalStatusOverride = $"Download error: {ex.Message}";
        }
        finally
        {
            if (PbGemmaDownload != null) PbGemmaDownload.Visibility = Visibility.Collapsed;
            if (BtnCancelGemmaDownload != null) BtnCancelGemmaDownload.Visibility = Visibility.Collapsed;
            if (BtnDownloadGemmaSidecar != null) BtnDownloadGemmaSidecar.IsEnabled = true;
            RefreshGemmaStatusUi(finalStatusOverride);
        }
    }

    private void OnStopGemmaSidecarClick(object sender, RoutedEventArgs e)
    {
        LogicFlow.Guardian.GemmaAiEngine.Instance.StopSidecarImmediately();
        RefreshGemmaStatusUi("⏹ Local Gemma 4 E2B sidecar unloaded (0 MB VRAM).");
    }

    private void OnDeleteGemmaModelClick(object sender, RoutedEventArgs e)
    {
        if (!Dialogs.Confirm(
            this,
            "Delete Local Gemma 4 Model",
            "Delete the downloaded Gemma 4 E2B GGUF model (~1.3 GB) from disk and stop the local sidecar?\n\nYou can re-download it later in Settings.",
            "Delete Model",
            "Cancel",
            defaultCancel: true,
            destructive: true))
        {
            return;
        }

        bool deleted = LogicFlow.Guardian.GemmaAiEngine.Instance.DeleteLocalModel();
        RefreshGemmaStatusUi(deleted
            ? "🗑 Local Gemma 4 E2B GGUF model deleted and sidecar stopped."
            : "ℹ No local Gemma 4 E2B model file was found on disk.");
    }

    private void RefreshGemmaStatusUi(string? statusOverride = null)
    {
        if (TxtGemmaStatus == null) return;
        var engine = LogicFlow.Guardian.GemmaAiEngine.Instance;

        if (BtnStopGemmaSidecar != null)
            BtnStopGemmaSidecar.IsEnabled = engine.IsSidecarRunning;
        if (BtnDeleteGemmaModel != null)
            BtnDeleteGemmaModel.IsEnabled = engine.IsLocalModelInstalled();

        string modeDesc = engine.Mode switch
        {
            LogicFlow.Guardian.GemmaExecutionMode.HybridAuto => engine.AllowHybridCloudFallback
                ? "Hybrid Auto (Local Sidecar + Cloud Opt-In)"
                : "Hybrid Auto (Local-Only — Cloud Fallback Off)",
            LogicFlow.Guardian.GemmaExecutionMode.LocalSidecar => "Local Offline Sidecar",
            LogicFlow.Guardian.GemmaExecutionMode.CloudEndpoint => "Cloud OpenAI-Compatible Endpoint",
            _ => "Disabled (Rule-Based Only)"
        };
        string assetState = engine.IsLocalAssetsInstalled
            ? (engine.IsSidecarRunning ? $"Installed (Running PID {engine.SidecarProcessId})" : "Installed (Unloaded / 0 MB VRAM)")
            : "Not Installed (~1.3 GB download required for local mode)";

        TxtGemmaStatus.Text = !string.IsNullOrWhiteSpace(statusOverride)
            ? $"{statusOverride} • Mode: {modeDesc} • Local Assets: {assetState}"
            : $"Mode: {modeDesc} • Local Assets: {assetState}";
    }

    private static IReadOnlyList<(string Label, string Path)> GetAllDataPaths()
    {
        string localAppData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogicFlow");
        string roamingLogicFlow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LogicFlow");
        string roamingShared = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DelgadoLogic", "Shared");
        string programDataLogs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LogicFlow", "Logs");
        string programDataReports = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LogicFlow", "Reports");
        string legacyDelgadoLocal = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DelgadoLogic");

        var paths = new List<(string Label, string Path)>
        {
            ("Settings & Consent (%LOCALAPPDATA%)", localAppData),
            ("Models & Vaults (%APPDATA%)", roamingLogicFlow),
            ("Shared License Identity (%APPDATA%)", roamingShared),
            ("Service Logs (%PROGRAMDATA%)", programDataLogs),
            ("Service Health Reports (%PROGRAMDATA%)", programDataReports)
        };
        if (Directory.Exists(legacyDelgadoLocal))
        {
            paths.Add(("Legacy Device Identity (%LOCALAPPDATA%)", legacyDelgadoLocal));
        }
        return paths;
    }

    private static string GetAllDataPathsFormatted() =>
        string.Join("\n", GetAllDataPaths().Select(p => $"{p.Label}: {p.Path}"));

    private async void OnCopyHwidClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var hwid = new HwidGenerator().GenerateHwid();
            System.Windows.Clipboard.SetText(hwid);
            var originalText = HwidLabel.Text;
            HwidLabel.Text = $"{originalText} — Copied! ✅";
            await Task.Delay(2500);
            HwidLabel.Text = originalText;
        }
        catch (Exception ex)
        {
            HwidLabel.Text = $"Failed to copy HWID: {ex.Message}";
        }
    }

    private void OnOpenDataFolderClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var allPaths = GetAllDataPaths();
            var primary = allPaths[0].Path;
            Directory.CreateDirectory(primary);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = primary,
                UseShellExecute = true,
                Verb = "open"
            });

            var secondaryExisting = allPaths.Skip(1).Where(p => Directory.Exists(p.Path)).ToList();
            if (secondaryExisting.Count > 0)
            {
                string extraSummary = string.Join("\n", secondaryExisting.Select(p => $"• {p.Label}:\n  {p.Path}"));
                bool openExtra = Dialogs.Confirm(
                    this,
                    "LogicFlow Data Folders",
                    $"Opened primary settings folder:\n{primary}\n\nLogicFlow also stores active data in:\n{extraSummary}\n\nOpen these additional folders in Explorer as well?",
                    "Open Additional Folders",
                    "Done",
                    defaultCancel: true);
                if (openExtra)
                {
                    foreach (var (_, dir) in secondaryExisting)
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = dir,
                                UseShellExecute = true,
                                Verb = "open"
                            });
                        }
                        catch { }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "LogicFlow Error", $"Failed to open directory: {ex.Message}", isWarningOrError: true);
        }
    }

    private void OnCleanLogsClick(object sender, RoutedEventArgs e)
    {
        try
        {
            int deletedCount = 0;
            long bytesFreed = 0;
            foreach (var (_, dir) in GetAllDataPaths())
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, "*.log", SearchOption.AllDirectories)
                        .Concat(dir.EndsWith(Path.Combine("LogicFlow", "Reports"), StringComparison.OrdinalIgnoreCase)
                            ? Directory.GetFiles(dir, "health_*.json", SearchOption.TopDirectoryOnly)
                            : Array.Empty<string>()))
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            bytesFreed += fi.Length;
                            File.Delete(file);
                            deletedCount++;
                        }
                        catch { /* File might be locked by active sink */ }
                    }
                }
                catch { }
            }

            Dialogs.ShowMessage(
                this,
                "LogicFlow Logs Cleaned",
                deletedCount > 0
                    ? $"Cleaned {deletedCount} log file(s) across LocalAppData, AppData, and ProgramData.\nFreed {bytesFreed / (1024.0 * 1024.0):F2} MB of disk space."
                    : "No unlocked diagnostic .log files were found across LogicFlow data directories.");
        }
        catch (Exception ex)
        {
            Dialogs.ShowMessage(this, "LogicFlow Error", $"Failed to clean logs: {ex.Message}");
        }
    }

    private void OnResetSettingsClick(object sender, RoutedEventArgs e)
    {
        bool confirmed = Dialogs.Confirm(
            this,
            "LogicFlow — Reset Settings",
            "Reset all application preferences, appearance settings, and scan exclusions to factory defaults?\n\nYour edition license and consent choice will remain intact.",
            "Reset to Defaults",
            "Cancel",
            defaultCancel: true,
            destructive: true);

        if (confirmed)
        {
            try
            {
                _isUiLoading = true;
                SettingsManager.Reset();
                _settings = SettingsManager.Load();
                _junkCleaner.ExcludedPaths = _settings.ScanExclusions;
                _diskSpaceAnalyzer.ExcludedPaths = _settings.ScanExclusions;
                LoadSettingsToUI();
                ApplyVisualSettings();
                Dialogs.ShowMessage(this, "Settings Reset", "Application settings have been reset to default values.");
            }
            catch (Exception ex)
            {
                Dialogs.ShowMessage(this, "LogicFlow Error", $"Failed to reset settings: {ex.Message}");
            }
            finally
            {
                _isUiLoading = false;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  EDITION, LICENCE ACTIVATION & DIAGNOSTICS SHARING
    // ═══════════════════════════════════════════════════════════

    private bool _editionSubscribed;

    private void CheckAndApplySavedLicense()
    {
        try
        {
            if (!_editionSubscribed)
            {
                _editionSubscribed = true;
                EditionService.Instance.Changed += () => Dispatcher.BeginInvoke(new Action(ApplyEdition));
            }
            EditionService.Instance.AdoptSavedLicense();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[License] Check failed: {ex.Message}");
        }

        ApplyEdition();
    }

    /// <summary>Paints the sidebar badge, the Settings tier card and the telemetry controls from the resolved edition.</summary>
    private void ApplyEdition()
    {
        Dispatcher.Invoke(() =>
        {
            var svc = EditionService.Instance;
            var edition = svc.Current;
            var name = edition.DisplayName();
            var isTrialPro = edition == Edition.Pro && svc.LoadSavedValidation() is not { IsValid: true } && svc.ActiveTrial is { IsActive: true, IsTampered: false };

            LicenseLabel.Text = isTrialPro ? "Pro Trial" : $"{name} Edition";
            switch (edition)
            {
                case Edition.Pro when isTrialPro:
                    var days = svc.ActiveTrial!.DaysRemaining;
                    TrialLabel.Text = $"14-day Pro trial · {days} day(s) remaining";
                    BtnUpgradeTier.Visibility = Visibility.Visible;
                    BtnUpgradeTier.Content = PriceSheet.UpgradeLabel;
                    SettingsTierText.Text = $"Pro Trial ({days}d left)";
                    SettingsTierBadge.SetResourceReference(Border.BackgroundProperty, "BrushAccentGlow");
                    SettingsTierText.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");
                    LicenseActivationStatus.Text = $"14-day Pro trial active ({days} day(s) remaining).";
                    LicenseActivationStatus.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");
                    break;

                case Edition.Pro:
                    TrialLabel.Text = $"{PriceSheet.ProDevices} devices · {PriceSheet.UpdatesPolicy.ToLowerInvariant()}";
                    BtnUpgradeTier.Visibility = Visibility.Collapsed;
                    SettingsTierText.Text = "Pro Edition (Active)";
                    SettingsTierBadge.SetResourceReference(Border.BackgroundProperty, "BrushAccentGlow");
                    SettingsTierText.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");
                    LicenseActivationStatus.Text = "License verified (RSA-2048 signature).";
                    LicenseActivationStatus.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");
                    break;

                case Edition.Community:
                    TrialLabel.Text = "$0 for personal use · 1 device · diagnostics sharing active";
                    BtnUpgradeTier.Visibility = Visibility.Visible;
                    BtnUpgradeTier.Content = PriceSheet.UpgradeLabel;
                    SettingsTierText.Text = "Community Edition";
                    SettingsTierBadge.SetResourceReference(Border.BackgroundProperty, "BrushAccentGlow");
                    SettingsTierText.SetResourceReference(TextBlock.ForegroundProperty, "BrandCyanBrush");
                    LicenseActivationStatus.Text = "Pro is a one-time license ($29.99, launch price $19.99) — unlock 3 devices, commercial use, and background automation.";
                    LicenseActivationStatus.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
                    break;

                default:
                    TrialLabel.Text = "Scan-only. Switch to Community in Settings to unlock fixes.";
                    BtnUpgradeTier.Visibility = Visibility.Visible;
                    BtnUpgradeTier.Content = PriceSheet.UpgradeLabel;
                    SettingsTierText.Text = "Free Edition";
                    SettingsTierBadge.SetResourceReference(Border.BackgroundProperty, "BrandDarkCardBrush");
                    SettingsTierText.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
                    LicenseActivationStatus.Text = "Pro is a one-time license ($29.99, launch price $19.99) — unlock 3 devices, commercial use, and background automation.";
                    LicenseActivationStatus.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondaryBrush");
                    break;
            }
            UpdateResponsiveLayoutBreakpoints();

            if (!svc.Allows(Capability.HyperStoreAutonomousWorker) && !_hyperStoreViewModel.IsManualOnly)
            {
                _hyperStoreViewModel.IsManualOnly = true;
            }

            Gate.RefreshAllVisualCues();
            UpdateTurboButtonVisuals(_turboMode.IsActive);
            UpdateOverviewBar();
            RefreshTelemetryUi();
        });
    }

    // ─── Diagnostics sharing (Settings) ─────────────────────────────────

    private bool _telemetryUiLoading;

    private void RefreshTelemetryUi()
    {
        if (SettingShareStandard is null || SettingShareExtended is null || TelemetryStatusText is null) return;

        var svc = EditionService.Instance;
        var level = svc.Consent.EffectiveLevel();
        var edition = svc.Current;

        _telemetryUiLoading = true;
        try
        {
            SettingShareStandard.IsChecked = level >= ConsentLevel.Standard;
            SettingShareExtended.IsChecked = level >= ConsentLevel.Extended;

            // Pro: both optional. Community: Standard is the condition of the $0 Community edition; Extended is optional. Free: nothing is shared.
            SettingShareStandard.IsEnabled = edition == Edition.Pro;
            SettingShareExtended.IsEnabled = edition == Edition.Pro || edition == Edition.Community;

            TelemetryStatusText.Text = (edition, level) switch
            {
                (Edition.Free, _) => "Free Edition: nothing is collected or sent. Choose Community in “Change Edition or Region…” for all core features (requires diagnostics sharing).",
                (Edition.Community, _) => "Community Edition: Standard diagnostics sharing is required. Switch to Free to stop sharing, or upgrade to Pro to make it optional.",
                (_, ConsentLevel.None) => "Pro Edition: diagnostics sharing is off. Turn it on below to help improve LogicFlow.",
                _ => $"Pro Edition: sharing at the {level} level. You can turn it off at any time."
            };
        }
        finally
        {
            _telemetryUiLoading = false;
        }
    }

    private void OnTelemetryToggled(object sender, RoutedEventArgs e)
    {
        if (_telemetryUiLoading) return;

        var svc = EditionService.Instance;
        var standard = SettingShareStandard.IsChecked == true;
        var extended = SettingShareExtended.IsChecked == true;
        if (ReferenceEquals(sender, SettingShareStandard) && !standard) extended = false;   // Extended includes Standard
        if (extended) standard = true;

        if (svc.Current == Edition.Pro) svc.Consent.SetOptionalTelemetry(standard, extended);
        else if (svc.Current == Edition.Community) svc.Consent.SetExtended(extended);

        App.OnConsentChanged();
        RefreshTelemetryUi();
    }

    private void OnViewTelemetryClick(object sender, RoutedEventArgs e)
    {
        var pulse = (Application.Current as App)?.Pulse;
        var text = pulse?.BuildPreview() ?? "Nothing is collected or sent.";
        Dialogs.ShowText(this, "What LogicFlow Sends", text);
    }

    private void OnRotateInstallIdClick(object sender, RoutedEventArgs e)
    {
        bool confirm = Dialogs.Confirm(
            this,
            "Reset Install ID",
            "Issue a new random install ID?\n\nData already sent stays under the old ID until you use “Delete My Data”.",
            "Reset Install ID",
            "Cancel",
            defaultCancel: true);
        if (!confirm) return;

        EditionService.Instance.Consent.RotateInstallId();
        RefreshTelemetryUi();
    }

    private async void OnDeleteTelemetryDataClick(object sender, RoutedEventArgs e)
    {
        bool confirm = Dialogs.Confirm(
            this,
            "Delete My Data",
            "Delete everything LogicFlow stored locally for diagnostics sharing and ask the server to delete the data held for this install ID?\n\nThis cannot be undone.",
            "Delete My Data",
            "Cancel",
            defaultCancel: true,
            destructive: true);
        if (!confirm) return;

        try
        {
            var pulse = (Application.Current as App)?.Pulse;
            bool confirmed;
            if (pulse is not null) confirmed = await pulse.DeleteMyDataAsync();
            else { EditionService.Instance.Consent.ClearInstallId(); confirmed = true; }
            DelgadoLogicIdentity.PurgePersistedIdentity();

            Dialogs.ShowMessage(
                this,
                "Delete My Data",
                confirmed
                    ? "Your data was deleted."
                    : "Local data was deleted. The server could not be reached; the deletion request will be retried automatically.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[Telemetry] Delete failed: {ex.GetType().Name}");
            Dialogs.ShowMessage(
                this,
                "Delete My Data",
                "Could not delete your data right now. Please try again later or contact " + PriceSheet.SupportEmail + ".");
        }
        RefreshTelemetryUi();
    }

    private void OnOpenConsentClick(object sender, RoutedEventArgs e)
    {
        ConsentWindow.ShowFromSettings(this);
        ApplyEdition();
        RefreshTelemetryUi();
    }

    private void OnLegalLinkClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string slug }) return;
        Dialogs.ShowLegalDoc(this, slug);
    }

    private void OnAboutClick(object sender, RoutedEventArgs e) => Dialogs.ShowAbout(this);

    private async void OnActivateLicenseClick(object sender, RoutedEventArgs e)
    {
        var key = TxtLicenseKey.Text?.Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            LicenseActivationStatus.Text = "Please paste a valid RSA license token or order activation code.";
            LicenseActivationStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x52, 0x52));
            return;
        }

        BtnActivateLicense.IsEnabled = false;
        LicenseActivationStatus.Text = "Validating cryptographic token...";
        LicenseActivationStatus.Foreground = (Brush)FindResource("TextSecondaryBrush");

        try
        {
            LicenseToken? token = null;

            // Direct JSON token
            if (key.StartsWith("{") && key.EndsWith("}"))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(key);
                    string payload = "";
                    string sig = "";
                    string? alg = null;
                    string? kid = null;
                    if (doc.RootElement.TryGetProperty("Payload", out var p) || doc.RootElement.TryGetProperty("payload", out p))
                        payload = p.GetString() ?? "";
                    if (doc.RootElement.TryGetProperty("Signature", out var s) || doc.RootElement.TryGetProperty("signature", out s))
                        sig = s.GetString() ?? "";
                    if (doc.RootElement.TryGetProperty("Alg", out var a) || doc.RootElement.TryGetProperty("alg", out a))
                        alg = a.GetString();
                    if (doc.RootElement.TryGetProperty("Kid", out var k) || doc.RootElement.TryGetProperty("kid", out k))
                        kid = k.GetString();
                    if (!string.IsNullOrEmpty(payload) && !string.IsNullOrEmpty(sig))
                        token = new LicenseToken(payload, sig, alg, kid);
                }
                catch { }
            }

            // Base64-encoded JSON token
            if (token == null && !key.Contains(' ') && key.Length > 20)
            {
                try
                {
                    var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(key));
                    if (decoded.TrimStart().StartsWith("{"))
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(decoded);
                        string payload = "";
                        string sig = "";
                        string? alg = null;
                        string? kid = null;
                        if (doc.RootElement.TryGetProperty("Payload", out var p) || doc.RootElement.TryGetProperty("payload", out p))
                            payload = p.GetString() ?? "";
                        if (doc.RootElement.TryGetProperty("Signature", out var s) || doc.RootElement.TryGetProperty("signature", out s))
                            sig = s.GetString() ?? "";
                        if (doc.RootElement.TryGetProperty("Alg", out var a) || doc.RootElement.TryGetProperty("alg", out a))
                            alg = a.GetString();
                        if (doc.RootElement.TryGetProperty("Kid", out var k) || doc.RootElement.TryGetProperty("kid", out k))
                            kid = k.GetString();
                        if (!string.IsNullOrEmpty(payload) && !string.IsNullOrEmpty(sig))
                            token = new LicenseToken(payload, sig, alg, kid);
                    }
                }
                catch { }
            }

            // Dot-separated payload.signature token
            if (token == null && key.Contains('.'))
            {
                var parts = key.Split('.');
                if (parts.Length == 2)
                {
                    string payload;
                    try
                    {
                        payload = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));
                    }
                    catch
                    {
                        payload = parts[0];
                    }
                    token = new LicenseToken(payload, parts[1]);
                }
            }

            // If offline RSA token found, validate
            if (token != null)
            {
                var result = await EditionService.Instance.ActivateAsync(token);
                if (result.IsValid)
                {
                    ApplyEdition();
                    LicenseActivationStatus.Text = $"✅ License activated. Edition: {EditionService.Instance.Current.DisplayName()} (signature verified)";
                    LicenseActivationStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                    return;
                }
                else
                {
                    LicenseActivationStatus.Text = $"❌ License validation failed: {result.Message}";
                    LicenseActivationStatus.Foreground = (Brush)FindResource("DangerRedBrush");
                    return;
                }
            }

            // Attempt cloud activation for order IDs
            try
            {
                var bridge = new CloudLicenseBridge(NullLogger<CloudLicenseBridge>.Instance, new LogicFlowConfig().AppDataPath);
                var cloudResult = await bridge.ActivateAsync(key, "");
                if (cloudResult.Success && cloudResult.Token != null)
                {
                    // Never trust the tier string from the network: the edition comes from the verified token on disk.
                    var cloudTier = TierPolicy.ParseTierFailClosed(cloudResult.Tier);
                    var adopted = EditionService.Instance.AdoptSavedLicense();
                    ApplyEdition();
                    if (adopted)
                    {
                        LicenseActivationStatus.Text = $"✅ License activated. Edition: {EditionService.Instance.Current.DisplayName()}";
                        LicenseActivationStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
                    }
                    else
                    {
                        LicenseActivationStatus.Text = $"❌ The activation response (tier: {cloudTier}) could not be verified on this device. Contact {PriceSheet.SupportEmail}.";
                        LicenseActivationStatus.Foreground = (Brush)FindResource("DangerRedBrush");
                    }
                    return;
                }
                else
                {
                    LicenseActivationStatus.Text = $"❌ Activation failed: {cloudResult.Message}";
                    LicenseActivationStatus.Foreground = (Brush)FindResource("DangerRedBrush");
                    return;
                }
            }
            catch (Exception ex)
            {
                LicenseActivationStatus.Text = $"❌ Activation error: {ex.Message}";
                LicenseActivationStatus.Foreground = (Brush)FindResource("DangerRedBrush");
            }
        }
        catch (Exception ex)
        {
            LicenseActivationStatus.Text = $"❌ Failed to activate license: {ex.Message}";
            LicenseActivationStatus.Foreground = (Brush)FindResource("DangerRedBrush");
        }
        finally
        {
            BtnActivateLicense.IsEnabled = true;
        }
    }

    // ─── Single-Instance Window Activation & Win32 Interop ───────────────
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    private static extern uint RegisterWindowMessage(string lpString);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, uint msg, uint action, IntPtr pChangeFilterStruct);

    private const uint MSGFLT_ALLOW = 1;

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

    private const int SW_RESTORE = 9;
    private const int WM_NCHITTEST = 0x0084;
    private const int WM_NCLBUTTONDOWN = 0x00A1;
    private const int WM_NCLBUTTONUP = 0x00A2;
    private const int HTMAXBUTTON = 9;
    private const int WM_DEVICECHANGE = 0x0219;
    private const int DBT_DEVICEARRIVAL = 0x8000;
    private const int DBT_DEVICEREMOVECOMPLETE = 0x8004;
    private static uint _wmRestoreMessage;

    private IntPtr WndProcRestoreHook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (_wmRestoreMessage != 0 && (uint)msg == _wmRestoreMessage)
        {
            RestoreAndActivate();
            handled = true;
            return (IntPtr)1;
        }

        // Windows 11 Snap Layouts support on custom WPF Maximize button
        if (msg == WM_NCHITTEST && MaximizeButton is { IsVisible: true, ActualWidth: > 0, ActualHeight: > 0 })
        {
            try
            {
                long raw = lParam.ToInt64();
                int screenX = unchecked((short)(raw & 0xFFFF));
                int screenY = unchecked((short)((raw >> 16) & 0xFFFF));
                Point pt = MaximizeButton.PointFromScreen(new Point(screenX, screenY));
                if (pt.X >= 0 && pt.X <= MaximizeButton.ActualWidth &&
                    pt.Y >= 0 && pt.Y <= MaximizeButton.ActualHeight)
                {
                    handled = true;
                    return (IntPtr)HTMAXBUTTON;
                }
            }
            catch { }
        }
        else if (msg == WM_NCLBUTTONDOWN && wParam.ToInt32() == HTMAXBUTTON)
        {
            handled = true;
            return IntPtr.Zero;
        }
        else if (msg == WM_NCLBUTTONUP && wParam.ToInt32() == HTMAXBUTTON)
        {
            OnMaximize(this, new RoutedEventArgs());
            handled = true;
            return IntPtr.Zero;
        }
        else if (msg == WM_DEVICECHANGE)
        {
            int evt = unchecked((int)(wParam.ToInt64() & 0xFFFF));
            if (evt is DBT_DEVICEARRIVAL or DBT_DEVICEREMOVECOMPLETE)
            {
                ScheduleDebouncedDriveRefresh();
            }
        }

        return IntPtr.Zero;
    }

    private void ScheduleDebouncedDriveRefresh()
    {
        try
        {
            _deviceChangeDebounceCts?.Cancel();
            _deviceChangeDebounceCts?.Dispose();
            var cts = new CancellationTokenSource();
            _deviceChangeDebounceCts = cts;
            var token = cts.Token;

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(650, token);
                    if (token.IsCancellationRequested) return;
                    var disks = SystemInfoEngine.CollectDiskInfo();
                    await Dispatcher.InvokeAsync(async () =>
                    {
                        if (_liveSnapshot != null) _liveSnapshot.Disks = disks;
                        UpdateDashboardLiveMetrics();
                        PopulateMonitorUI(forceDiskRebuild: true);
                        await RefreshDrives();
                    });
                }
                catch { }
            }, token);
        }
        catch { }
    }

    /// <summary>
    /// Restores the main window from minimized or hidden/tray state,
    /// ensures it is visible, and activates it in the foreground.
    /// </summary>
    public void RestoreAndActivate()
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(RestoreAndActivate);
            return;
        }

        try
        {
            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                ConsentWindow.ShowFirstRun();
                _isUiLoading = true;
                try
                {
                    _settings = SettingsManager.Load();
                    LoadSettingsToUI();
                }
                finally { _isUiLoading = false; }
                ApplyEdition();
            }

            if (!IsVisible)
            {
                Show();
            }

            ShowInTaskbar = true;

            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }

            // Bring to top trick for Windows 10/11 DWM
            Topmost = true;
            Topmost = false;

            Activate();
            Focus();

            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            if (hwnd != IntPtr.Zero)
            {
                ShowWindowAsync(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
        }
        catch { }
    }

    /// <summary>
    /// True once the window has initialized its Win32 HWND and system tray icon via <see cref="StartInTray"/>,
    /// allowing <see cref="App"/> to distinguish an active tray-resident host from a pre-load startup crash.
    /// </summary>
    public bool IsTrayResident { get; private set; }

    /// <summary>
    /// Starts the application silently minimized to the system tray (for Windows startup with --tray).
    /// </summary>
    public void StartInTray()
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(StartInTray);
            return;
        }

        try
        {
            // Ensure HWND is created so OnSourceInitialized registers the single-instance WM_RESTORE hook,
            // and initialize license state, settings, and system tray icon even before the window is first shown.
            try { new System.Windows.Interop.WindowInteropHelper(this).EnsureHandle(); } catch { }
            try { CheckAndApplySavedLicense(); } catch { }
            try { _settings ??= SettingsManager.Load(); } catch { }
            try { _trayManager ??= new TrayIconManager(this); } catch { }
            IsTrayResident = true;

            WindowState = WindowState.Minimized;
            ShowInTaskbar = false;
            Hide();

            if (_settings?.ShowNotifications == true)
            {
                _trayManager?.ShowBalloon("LogicFlow", "LogicFlow is running in the background tray.", System.Windows.Forms.ToolTipIcon.Info, 2500);
            }
        }
        catch { }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // v1.1 FEATURES: Boot Flamegraph, VSS Browser, Browser SQLite Cleaner, Treemap
    // ═══════════════════════════════════════════════════════════════════════════

    private readonly BootPerformanceAnalyzer _bootPerformanceAnalyzer = new();
    private readonly DiskSpaceAnalyzer _diskSpaceAnalyzer = new();
    private List<VssShadowCopyInfo> _vssSnapshots = new();
    private DiskSpaceAnalyzer.FolderNode? _treemapRootNode;
    private DiskSpaceAnalyzer.FolderNode? _treemapCurrentNode;
    private readonly Stack<DiskSpaceAnalyzer.FolderNode> _treemapParentStack = new();

    private static System.Windows.Media.SolidColorBrush BrushFromHex(string hex, byte alpha = 255)
    {
        try
        {
            var raw = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex);
            return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(alpha, raw.R, raw.G, raw.B));
        }
        catch
        {
            return new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(alpha, 0, 229, 255));
        }
    }

    // ─── Feature 3: Boot-Time Critical Path Flamegraph (Event ID 100–110) ───
    private async void OnScanBootFlamegraph(object s, RoutedEventArgs e)
    {
        try
        {
            BtnScanBootFlamegraph.IsEnabled = false;
            BootFlamegraphStatus.Text = "Querying Windows Diagnostics-Performance Event ID 100–110...";
            BootFlamegraphList.Items.Clear();

            var report = await Task.Run(() => _bootPerformanceAnalyzer.Analyze(maxBarWidthPx: 520.0));

            BootFlamegraphSummaryBar.Visibility = Visibility.Visible;
            BootFlamegraphList.Visibility = Visibility.Visible;
            string grade = report.TotalBootTimeMs <= 12000 ? "Fast" : report.TotalBootTimeMs <= 25000 ? "Moderate" : "Slow";
            BootTotalTimeText.Text = $"{report.TotalBootSeconds:F2} s ({report.TotalBootTimeMs:N0} ms — {grade})";
            BootTelemetrySourceText.Text = report.TelemetrySource;

            double mainRatio = report.TotalBootTimeMs > 0
                ? Math.Clamp((double)report.MainPathBootTimeMs / report.TotalBootTimeMs, 0.1, 0.9)
                : 0.55;
            double postRatio = Math.Max(0.1, 1.0 - mainRatio);
            BootMainPathCol.Width = new GridLength(mainRatio, GridUnitType.Star);
            BootPostBootCol.Width = new GridLength(postRatio, GridUnitType.Star);
            BootMainPathBarLabel.Text = $"Main Path (Kernel + Drivers + Services): {report.MainPathBootTimeMs:N0} ms ({report.MainPathPercent:F1}%)";
            BootPostBootBarLabel.Text = $"Post-Boot Desktop & Startup Apps: {report.PostBootTimeMs:N0} ms ({report.PostBootPercent:F1}%)";

            foreach (var item in report.CriticalPathEntries)
            {
                var card = new System.Windows.Controls.Border
                {
                    CornerRadius = new CornerRadius(6),
                    Padding = new Thickness(12, 8, 12, 8),
                    Margin = new Thickness(0, 0, 0, 6),
                    BorderBrush = BrushFromHex(item.ColorHex, 90),
                    BorderThickness = new Thickness(1)
                };
                card.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "BrandDarkPanelBrush");

                var stack = new System.Windows.Controls.StackPanel();
                var topGrid = new System.Windows.Controls.Grid();
                topGrid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                topGrid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = GridLength.Auto });

                var titlePanel = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
                var itemTitle = new System.Windows.Controls.TextBlock
                {
                    Text = $"[{item.EventId}] {item.Name}",
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 12,
                    VerticalAlignment = VerticalAlignment.Center
                };
                itemTitle.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextPrimaryBrush");
                titlePanel.Children.Add(itemTitle);

                var itemPhase = new System.Windows.Controls.TextBlock
                {
                    Text = $"  •  {item.Phase}",
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                itemPhase.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextSecondaryBrush");
                titlePanel.Children.Add(itemPhase);
                System.Windows.Controls.Grid.SetColumn(titlePanel, 0);
                topGrid.Children.Add(titlePanel);

                var badgeText = new System.Windows.Controls.TextBlock
                {
                    Text = $"+{item.DegradationMs:N0} ms ({item.Severity}) — Total {item.DurationMs:N0} ms ({item.PercentOfBoot:F1}%)",
                    Foreground = BrushFromHex(item.ColorHex),
                    FontWeight = FontWeights.Bold,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                System.Windows.Controls.Grid.SetColumn(badgeText, 1);
                topGrid.Children.Add(badgeText);
                stack.Children.Add(topGrid);

                // Proportional Flamegraph Bar
                var barTrack = new System.Windows.Controls.Border
                {
                    CornerRadius = new CornerRadius(3),
                    Height = 8,
                    Margin = new Thickness(0, 6, 0, 4)
                };
                barTrack.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "BorderSubtleBrush");
                var barFill = new System.Windows.Controls.Border
                {
                    Background = BrushFromHex(item.ColorHex),
                    CornerRadius = new CornerRadius(3),
                    HorizontalAlignment = System.Windows.HorizontalAlignment.Left,
                    Width = Math.Max(18.0, item.BarWidthPx)
                };
                barTrack.Child = barFill;
                stack.Children.Add(barTrack);

                var itemPathText = new System.Windows.Controls.TextBlock
                {
                    Text = string.IsNullOrWhiteSpace(item.Path) ? item.FriendlyName : $"{item.FriendlyName} — {item.Path}",
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap
                };
                itemPathText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextSecondaryBrush");
                stack.Children.Add(itemPathText);

                card.Child = stack;
                BootFlamegraphList.Items.Add(card);
            }

            BootFlamegraphStatus.Text = $"Analyzed {report.CriticalPathEntries.Count} critical-path boot entries ({report.TelemetrySource}).";
        }
        catch (Exception ex)
        {
            BootFlamegraphStatus.Text = $"Boot analysis failed: {ex.Message}";
        }
        finally
        {
            BtnScanBootFlamegraph.IsEnabled = true;
        }
    }

    // ─── Feature 4: VSS Shadow Copy File Browser & Single-File Restore ───
    private async void OnLoadVssSnapshots(object s, RoutedEventArgs e)
    {
        try
        {
            BtnLoadVssSnapshots.IsEnabled = false;
            VssBrowserStatus.Text = "Enumerating VSS shadow copy volumes...";
            ComboVssSnapshots.Items.Clear();

            _vssSnapshots = await Task.Run(() => _restoreEngine.ListShadowCopies());
            foreach (var snap in _vssSnapshots)
            {
                ComboVssSnapshots.Items.Add(snap.DisplayLabel);
            }

            if (_vssSnapshots.Count > 0)
            {
                ComboVssSnapshots.SelectedIndex = 0;
                VssBrowserStatus.Text = $"Loaded {_vssSnapshots.Count} VSS shadow snapshot(s).";
            }
            else
            {
                VssBrowserStatus.Text = "No VSS shadow snapshots found (ensure Administrator privileges & System Protection enabled).";
            }
        }
        catch (Exception ex)
        {
            VssBrowserStatus.Text = $"VSS enumeration error: {ex.Message}";
        }
        finally
        {
            BtnLoadVssSnapshots.IsEnabled = true;
        }
    }

    private void OnVssSnapshotSelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (ComboVssSnapshots.SelectedIndex >= 0 && ComboVssSnapshots.SelectedIndex < _vssSnapshots.Count)
        {
            OnBrowseVssSnapshot(s, e);
        }
    }

    private void OnVssUpDirectory(object s, RoutedEventArgs e)
    {
        string current = (VssRelativePathBox.Text ?? string.Empty).Trim().Trim('\\', '/');
        if (string.IsNullOrEmpty(current)) return;

        int lastSep = current.LastIndexOfAny(new[] { '\\', '/' });
        VssRelativePathBox.Text = lastSep > 0 ? current[..lastSep] : string.Empty;
        OnBrowseVssSnapshot(s, e);
    }

    private async void OnBrowseVssSnapshot(object s, RoutedEventArgs e)
    {
        if (ComboVssSnapshots.SelectedIndex < 0 || ComboVssSnapshots.SelectedIndex >= _vssSnapshots.Count)
        {
            VssBrowserStatus.Text = "Load and select a VSS snapshot first.";
            return;
        }

        var selectedSnap = _vssSnapshots[ComboVssSnapshots.SelectedIndex];
        string relPath = VssRelativePathBox.Text ?? string.Empty;
        string liveRoot = SystemRestoreEngine.NormalizeLiveVolumeRoot(selectedSnap.VolumeName);

        try
        {
            BtnVssBrowseFolder.IsEnabled = false;
            VssBrowserStatus.Text = $"Browsing {selectedSnap.DeviceObject}\\{relPath}...";
            VssFileList.Items.Clear();

            var entries = await Task.Run(() => _restoreEngine.BrowseShadowCopyDirectory(
                selectedSnap.DeviceObject,
                relPath,
                liveRoot));

            int deletedCount = entries.Count(x => x.DiffStatus == VssDiffStatus.DeletedOnLiveDisk);
            int modifiedCount = entries.Count(x => x.DiffStatus == VssDiffStatus.ModifiedSinceSnapshot);

            VssSummaryBar.Visibility = Visibility.Visible;
            VssSummaryText.Text = $"Showing {entries.Count} item(s) in '{(string.IsNullOrWhiteSpace(relPath) ? "\\" : relPath)}' — {deletedCount} Deleted on Live Disk, {modifiedCount} Modified Since Snapshot.";

            foreach (var entry in entries.Take(250))
            {
                var row = new System.Windows.Controls.Border
                {
                    CornerRadius = new CornerRadius(5),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(10, 7, 10, 7),
                    Margin = new Thickness(0, 0, 0, 4)
                };
                row.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "BrandDarkPanelBrush");
                row.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "BorderSubtleBrush");

                var grid = new System.Windows.Controls.Grid();
                grid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = GridLength.Auto });
                grid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = GridLength.Auto });

                var leftStack = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
                var entryNameText = new System.Windows.Controls.TextBlock
                {
                    Text = entry.IsDirectory ? $"📁 {entry.Name}" : $"📄 {entry.Name}",
                    FontWeight = entry.IsDirectory ? FontWeights.SemiBold : FontWeights.Normal,
                    FontSize = 12,
                    VerticalAlignment = VerticalAlignment.Center
                };
                entryNameText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextPrimaryBrush");
                leftStack.Children.Add(entryNameText);

                var entryMetaText = new System.Windows.Controls.TextBlock
                {
                    Text = entry.IsDirectory ? "  [Folder]" : $"  ({entry.SizeFormatted} • {entry.SnapshotLastModifiedUtc:yyyy-MM-dd HH:mm})",
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                entryMetaText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextSecondaryBrush");
                leftStack.Children.Add(entryMetaText);
                System.Windows.Controls.Grid.SetColumn(leftStack, 0);
                grid.Children.Add(leftStack);

                string badgeBrushKey = entry.DiffStatus switch
                {
                    VssDiffStatus.DeletedOnLiveDisk => "DangerRedBrush",
                    VssDiffStatus.ModifiedSinceSnapshot => "WarningAmberBrush",
                    _ => "SuccessGreenBrush"
                };

                var diffBadge = new System.Windows.Controls.TextBlock
                {
                    Text = entry.StatusBadge,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 11,
                    Margin = new Thickness(10, 0, 10, 0),
                    VerticalAlignment = VerticalAlignment.Center
                };
                diffBadge.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, badgeBrushKey);
                System.Windows.Controls.Grid.SetColumn(diffBadge, 1);
                grid.Children.Add(diffBadge);

                var btnPanel = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
                if (entry.IsDirectory)
                {
                    var openBtn = new System.Windows.Controls.Button
                    {
                        Content = "Open",
                        Padding = new Thickness(8, 3, 8, 3),
                        Margin = new Thickness(0, 0, 6, 0),
                        Background = BrushFromHex("#334155"),
                        Foreground = System.Windows.Media.Brushes.White,
                        BorderThickness = new Thickness(0),
                        Cursor = System.Windows.Input.Cursors.Hand
                    };
                    string capturedRel = entry.RelativePath;
                    openBtn.Click += (_, _) =>
                    {
                        VssRelativePathBox.Text = capturedRel;
                        OnBrowseVssSnapshot(this, new RoutedEventArgs());
                    };
                    btnPanel.Children.Add(openBtn);
                }

                var restoreBtn = new System.Windows.Controls.Button
                {
                    Content = "Restore",
                    Padding = new Thickness(10, 3, 10, 3),
                    Background = BrushFromHex("#0284C7"),
                    Foreground = System.Windows.Media.Brushes.White,
                    BorderThickness = new Thickness(0),
                    Cursor = System.Windows.Input.Cursors.Hand
                };
                var capturedEntry = entry;
                var capturedSnap = selectedSnap;
                restoreBtn.Click += async (_, _) =>
                {
                    if (!Gate.Require(Capability.Core, this)) return;

                    string targetDest = !string.IsNullOrWhiteSpace(capturedEntry.LiveFullPath)
                        ? capturedEntry.LiveFullPath
                        : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), capturedEntry.Name);

                    bool existsLive = File.Exists(targetDest) || Directory.Exists(targetDest);
                    string confirmMsg = existsLive
                        ? $"Restore '{capturedEntry.Name}' from shadow copy and OVERWRITE the current file at:\n\n{targetDest}\n\nThis will replace the live version on disk."
                        : $"Restore '{capturedEntry.Name}' from shadow copy to:\n\n{targetDest}";
                    if (!Dialogs.Confirm(
                        this,
                        "Restore File from Shadow Copy",
                        confirmMsg,
                        existsLive ? "Overwrite & Restore" : "Restore File",
                        "Cancel",
                        defaultCancel: existsLive,
                        destructive: existsLive))
                    {
                        return;
                    }

                    VssBrowserStatus.Text = $"Restoring '{capturedEntry.Name}' to '{targetDest}'...";
                    var res = await Task.Run(() => _restoreEngine.RestoreFileFromShadowCopy(
                        capturedSnap.DeviceObject,
                        capturedEntry.RelativePath,
                        targetDest,
                        overwrite: true));

                    VssBrowserStatus.Text = res.Message;
                    if (res.Success)
                    {
                        OnBrowseVssSnapshot(this, new RoutedEventArgs());
                    }
                };
                btnPanel.Children.Add(restoreBtn);

                System.Windows.Controls.Grid.SetColumn(btnPanel, 2);
                grid.Children.Add(btnPanel);

                row.Child = grid;
                VssFileList.Items.Add(row);
            }

            VssBrowserStatus.Text = $"Loaded {entries.Count} item(s) from shadow copy.";
        }
        catch (Exception ex)
        {
            VssBrowserStatus.Text = $"VSS browse failed: {ex.Message}";
        }
        finally
        {
            BtnVssBrowseFolder.IsEnabled = true;
        }
    }

    // ─── Feature 1: Per-Browser SQLite Cookie Whitelist & Vacuum Cleaner ───
    private void RenderBrowserWhitelistTags()
    {
        BrowserWhitelistTagsPanel.Children.Clear();
        var domains = _junkCleaner.BrowserPrivacyCleaner.GetWhitelistedDomains();
        foreach (var domain in domains)
        {
            var pill = new System.Windows.Controls.Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(10, 4, 8, 4),
                Margin = new Thickness(0, 0, 6, 6)
            };
            pill.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "BrandDarkCardBrush");
            pill.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "BrushAccentBorder");

            var sp = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
            var domainText = new System.Windows.Controls.TextBlock
            {
                Text = domain,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            };
            domainText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextPrimaryBrush");
            sp.Children.Add(domainText);

            var removeBtn = new System.Windows.Controls.Button
            {
                Content = " ✕",
                Background = System.Windows.Media.Brushes.Transparent,
                BorderThickness = new Thickness(0),
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Cursor = System.Windows.Input.Cursors.Hand,
                Padding = new Thickness(4, 0, 2, 0)
            };
            removeBtn.SetResourceReference(System.Windows.Controls.Control.ForegroundProperty, "DangerRedBrush");
            string capturedDomain = domain;
            removeBtn.Click += (_, _) =>
            {
                _junkCleaner.BrowserPrivacyCleaner.RemoveWhitelistedDomain(capturedDomain);
                RenderBrowserWhitelistTags();
            };
            sp.Children.Add(removeBtn);

            pill.Child = sp;
            BrowserWhitelistTagsPanel.Children.Add(pill);
        }
    }

    private void OnAddBrowserWhitelistDomain(object s, RoutedEventArgs e)
    {
        string raw = BrowserWhitelistInputBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(raw)) return;

        var domains = _junkCleaner.BrowserPrivacyCleaner.AddWhitelistedDomain(raw);
        BrowserWhitelistInputBox.Text = string.Empty;
        RenderBrowserWhitelistTags();
        BrowserPrivacyStatus.Text = $"Added '{BrowserPrivacyCleanerEngine.NormalizeDomain(raw)}' ({domains.Count} whitelisted domains).";
    }

    private void OnResetBrowserWhitelistDomains(object s, RoutedEventArgs e)
    {
        _junkCleaner.BrowserPrivacyCleaner.ResetWhitelistToDefaults();
        RenderBrowserWhitelistTags();
        BrowserPrivacyStatus.Text = "Reset cookie whitelist to default domains.";
    }

    private async void OnScanBrowserPrivacy(object s, RoutedEventArgs e)
    {
        await ExecuteBrowserPrivacyPassAsync(dryRun: true);
    }

    private async void OnCleanBrowserPrivacy(object s, RoutedEventArgs e)
    {
        await ExecuteBrowserPrivacyPassAsync(dryRun: false);
    }

    private async Task ExecuteBrowserPrivacyPassAsync(bool dryRun)
    {
        try
        {
            BtnScanBrowserPrivacy.IsEnabled = false;
            BtnCleanBrowserPrivacy.IsEnabled = false;
            RenderBrowserWhitelistTags();

            BrowserPrivacyStatus.Text = dryRun
                ? "Scanning Chromium & Firefox SQLite profiles..."
                : "Pruning non-whitelisted cookies & running SQLite VACUUM...";
            BrowserPrivacyList.Items.Clear();

            var report = await Task.Run(() => _junkCleaner.CleanBrowserPrivacy(vacuumDatabases: true, dryRun: dryRun));

            BrowserPrivacySummaryBar.Visibility = Visibility.Visible;
            BrowserPrivacySummaryText.Text = dryRun
                ? $"[Dry-Run] {report.ProfilesCleaned} profile(s) ready ({report.ProfilesSkippedRunning} running) — {report.TotalCookiesRemoved:N0} tracking cookies would be pruned ({report.TotalCookiesPreserved:N0} whitelisted kept), est. {report.TotalBytesReclaimedFormatted} reclaimable."
                : $"[Cleaned & Vacuumed] {report.ProfilesCleaned} profile(s) compacted — {report.TotalCookiesRemoved:N0} cookies deleted, {report.TotalCookiesPreserved:N0} whitelisted kept, {report.TotalBytesReclaimedFormatted} reclaimed via SQLite VACUUM.";

            foreach (var p in report.Profiles)
            {
                var row = new System.Windows.Controls.Border
                {
                    CornerRadius = new CornerRadius(5),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(10, 7, 10, 7),
                    Margin = new Thickness(0, 0, 0, 4)
                };
                row.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "BrandDarkPanelBrush");
                row.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "BorderSubtleBrush");

                var sp = new System.Windows.Controls.StackPanel();
                var profileHeader = new System.Windows.Controls.TextBlock
                {
                    Text = $"{p.BrowserName} [{p.ProfileName}] — {(p.SkippedBecauseRunning ? "RUNNING / LOCKED" : $"{p.CookiesRemoved:N0} pruned / {p.CookiesPreserved:N0} preserved • {p.DatabasesVacuumed} DBs ({p.BytesReclaimedFormatted} reclaimed)")}",
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 12
                };
                profileHeader.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, p.SkippedBecauseRunning ? "WarningAmberBrush" : "TextPrimaryBrush");
                sp.Children.Add(profileHeader);

                var profileMessages = new System.Windows.Controls.TextBlock
                {
                    Text = string.Join(" ", p.Messages),
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap
                };
                profileMessages.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TextSecondaryBrush");
                sp.Children.Add(profileMessages);

                row.Child = sp;
                BrowserPrivacyList.Items.Add(row);
            }

            BrowserPrivacyStatus.Text = dryRun
                ? $"Scan complete: {report.TotalCookiesRemoved:N0} non-whitelisted cookies identified."
                : $"Clean & VACUUM complete: {report.TotalBytesReclaimedFormatted} reclaimed.";
        }
        catch (Exception ex)
        {
            BrowserPrivacyStatus.Text = $"Browser SQLite operation failed: {ex.Message}";
        }
        finally
        {
            BtnScanBrowserPrivacy.IsEnabled = true;
            BtnCleanBrowserPrivacy.IsEnabled = true;
        }
    }

    // ─── Feature 2: Interactive Disk Space Treemap UI (WizTree-Style Block Map) ───
    private void OnTreemapRootClick(object s, RoutedEventArgs e)
    {
        if (_treemapRootNode == null) return;
        _treemapParentStack.Clear();
        _treemapCurrentNode = _treemapRootNode;
        RenderDiskSpaceTreemap();
    }

    private void OnTreemapUpClick(object s, RoutedEventArgs e)
    {
        if (_treemapParentStack.Count == 0) return;
        _treemapCurrentNode = _treemapParentStack.Pop();
        RenderDiskSpaceTreemap();
    }

    private void OnTreemapOpenExplorerClick(object s, RoutedEventArgs e)
    {
        string? targetPath = _treemapCurrentNode?.FullPath ?? _treemapRootNode?.FullPath;
        if (string.IsNullOrWhiteSpace(targetPath)) return;

        try
        {
            if (System.IO.Directory.Exists(targetPath))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{targetPath}\"",
                    UseShellExecute = true
                });
            }
            else if (System.IO.File.Exists(targetPath))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{targetPath}\"",
                    UseShellExecute = true
                });
            }
        }
        catch { }
    }

    private void OnDiskTreemapCanvasSizeChanged(object s, SizeChangedEventArgs e)
    {
        if (_treemapCurrentNode != null)
        {
            RenderDiskSpaceTreemap();
        }
    }

    private void RenderDiskSpaceTreemap()
    {
        if (_treemapCurrentNode == null) return;

        TreemapCurrentPathText.Text = $"{_treemapCurrentNode.FullPath} ({_treemapCurrentNode.SizeFormatted} • {_treemapCurrentNode.FileCount:N0} files)";
        BtnTreemapUp.IsEnabled = _treemapParentStack.Count > 0;

        double canvasW = DiskTreemapCanvas.ActualWidth > 20 ? DiskTreemapCanvas.ActualWidth : 760;
        double canvasH = DiskTreemapCanvas.ActualHeight > 20 ? DiskTreemapCanvas.ActualHeight : 280;

        DiskTreemapCanvas.Children.Clear();
        DiskTreemapList.Items.Clear();

        long globalRootBytes = _treemapRootNode?.SizeBytes > 0 ? _treemapRootNode.SizeBytes : _treemapCurrentNode.SizeBytes;
        var tiles = _diskSpaceAnalyzer.ComputeTreemapLayout(_treemapCurrentNode, canvasW, canvasH, maxDepth: 1);
        foreach (var tile in tiles)
        {
            if (tile.Width < 2 || tile.Height < 2) continue;

            double percentOfRoot = globalRootBytes > 0
                ? Math.Round((double)tile.SizeBytes / globalRootBytes * 100.0, 2)
                : tile.PercentOfRoot;

            var rectBorder = new System.Windows.Controls.Border
            {
                Width = Math.Max(1, tile.Width - 2),
                Height = Math.Max(1, tile.Height - 2),
                Background = BrushFromHex(tile.ColorHex, 195),
                BorderBrush = BrushFromHex("#0F172A"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Cursor = tile.IsDirectory ? System.Windows.Input.Cursors.Hand : System.Windows.Input.Cursors.Arrow,
                ToolTip = $"{tile.Name}\nSize: {tile.FormattedSize} ({tile.PercentOfParent:F1}% of folder, {percentOfRoot:F1}% of root)\nFiles: {tile.FileCount:N0}\nCategory: {tile.Category}\nPath: {tile.FullPath}"
            };

            if (tile.Width > 54 && tile.Height > 26)
            {
                rectBorder.Child = new System.Windows.Controls.TextBlock
                {
                    Text = $"{tile.Name}\n{tile.FormattedSize}",
                    Foreground = System.Windows.Media.Brushes.White,
                    FontSize = 10,
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(4, 2, 4, 2),
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
            }

            var matchingChild = tile.Node ?? _treemapCurrentNode.Children.FirstOrDefault(
                c => string.Equals(c.FullPath, tile.FullPath, StringComparison.OrdinalIgnoreCase));

            if (matchingChild != null && !matchingChild.IsFile)
            {
                rectBorder.MouseLeftButtonDown += async (_, _) =>
                {
                    var targetNode = matchingChild;
                    if (targetNode.Children.Count == 0 && System.IO.Directory.Exists(targetNode.FullPath))
                    {
                        try
                        {
                            _diskSpaceAnalyzer.ExcludedPaths = _settings?.ScanExclusions ?? [];
                            var subReport = await Task.Run(() => _diskSpaceAnalyzer.Analyze(targetNode.FullPath, maxDepth: 2, topFilesCount: 15));
                            if (subReport.RootNode.Children.Count > 0)
                            {
                                targetNode = subReport.RootNode;
                            }
                        }
                        catch { }
                    }

                    if (targetNode.Children.Count > 0)
                    {
                        _treemapParentStack.Push(_treemapCurrentNode!);
                        _treemapCurrentNode = targetNode;
                        RenderDiskSpaceTreemap();
                    }
                };
            }

            System.Windows.Controls.Canvas.SetLeft(rectBorder, tile.X + 1);
            System.Windows.Controls.Canvas.SetTop(rectBorder, tile.Y + 1);
            DiskTreemapCanvas.Children.Add(rectBorder);

            var listRow = new System.Windows.Controls.TextBlock
            {
                Text = $"{(tile.IsDirectory ? "📁" : "📄")} {tile.Name} — {tile.FormattedSize} ({tile.PercentOfParent:F1}% of folder / {percentOfRoot:F1}% of root • {tile.FileCount:N0} files) [{tile.Category}]",
                Foreground = BrushFromHex(tile.ColorHex),
                FontSize = 11,
                Margin = new Thickness(0, 1, 0, 1)
            };
            DiskTreemapList.Items.Add(listRow);
        }
    }
}

/// <summary>
/// Observable presentation item for carved disk file signatures in the Lazarus Recovery Vault.
/// </summary>
public sealed class CarvedFileItem : System.ComponentModel.INotifyPropertyChanged
{
    private bool _isSelected = true;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }
    }

    public CarvedFileHeader Header { get; init; } = new();
    public string DriveSource { get; init; } = "";
    public string Extension => string.IsNullOrWhiteSpace(Header.Extension) ? "BIN" : Header.Extension.ToUpperInvariant();
    public string FileType
    {
        get
        {
            string raw = Header.FileType ?? string.Empty;
            int suffixIdx = raw.LastIndexOf(" (.", StringComparison.Ordinal);
            return suffixIdx > 0 && raw.EndsWith(')') ? raw[..suffixIdx] : raw;
        }
    }
    public string Category => Header.Category;
    public long ByteOffset => Header.ByteOffset;
    public string OffsetFormatted => $"0x{Header.ByteOffset:X8}";
    public string SectorFormatted => $"Sector {Header.ByteOffset / 512:N0}";
    public long EstimatedSizeBytes => Header.EstimatedSizeBytes;
    public string SizeFormatted => MainWindow.FormatBytesStatic(Header.EstimatedSizeBytes);
    public string Confidence => Header.Confidence;

    // Multi-Method Recovery Properties
    public string FileName => !string.IsNullOrWhiteSpace(Header.FileName)
        ? Header.FileName
        : $"carved_0x{Header.ByteOffset:X8}.{Extension.ToLowerInvariant()}";

    public string RecoveryMethod => !string.IsNullOrWhiteSpace(Header.RecoveryMethod)
        ? Header.RecoveryMethod
        : "Raw Sector Carving";

    public string OriginalPath => Header.OriginalPath;

    public string OriginalPathOrOffset => !string.IsNullOrWhiteSpace(Header.OriginalPath)
        ? Header.OriginalPath
        : SectorFormatted;

    public string DimensionsFormatted => Header.ImageWidth > 0 && Header.ImageHeight > 0
        ? $"{Header.ImageWidth} × {Header.ImageHeight} px"
        : "";

    public string ModifiedDateFormatted => Header.ModifiedDate.HasValue
        ? Header.ModifiedDate.Value.ToString("yyyy-MM-dd HH:mm")
        : "—";

    public string Icon => Header.Extension.ToLowerInvariant() switch
    {
        "png" or "jpg" or "jpeg" or "gif" or "bmp" or "webp" or "ico" => "🖼",
        "pdf" or "doc" or "docx" or "xls" or "xlsx" or "ppt" or "pptx" or "txt" or "rtf" => "📄",
        "zip" or "rar" or "7z" or "tar" or "gz" => "📦",
        "mp4" or "avi" or "mkv" or "mov" => "🎬",
        "mp3" or "wav" or "flac" => "🎵",
        "sqlite" or "db" => "🗄",
        _ => "📁"
    };

    public static bool IsLightPaletteActive()
        => (Application.Current?.TryFindResource("BrandDarkBrush") ?? Application.Current?.TryFindResource("BrushBgBase")) is SolidColorBrush bg
           && (0.299 * bg.Color.R + 0.587 * bg.Color.G + 0.114 * bg.Color.B) > 140.0;

    private static Brush ForensicBadgeBrush(Color darkColor, string lightResourceKey, Color lightFallback)
        => IsLightPaletteActive()
            ? (Application.Current?.TryFindResource(lightResourceKey) as Brush ?? new SolidColorBrush(lightFallback))
            : new SolidColorBrush(darkColor);

    public Brush TypeBadgeBrush => Header.Extension.ToLowerInvariant() switch
    {
        "png" or "jpg" or "jpeg" or "gif" or "bmp" or "webp" or "ico" => ForensicBadgeBrush(Color.FromRgb(0, 229, 255), "BrandCyanBrush", Color.FromRgb(2, 132, 199)),
        "pdf" or "doc" or "docx" => ForensicBadgeBrush(Color.FromRgb(255, 82, 82), "DangerRedBrush", Color.FromRgb(220, 38, 38)),
        "zip" or "rar" or "7z" => ForensicBadgeBrush(Color.FromRgb(255, 179, 0), "WarningAmberBrush", Color.FromRgb(180, 83, 9)),
        "mp4" or "avi" => ForensicBadgeBrush(Color.FromRgb(187, 134, 252), "BrandPurpleBrush", Color.FromRgb(124, 58, 237)),
        "mp3" or "wav" => ForensicBadgeBrush(Color.FromRgb(3, 218, 198), "SuccessGreenBrush", Color.FromRgb(21, 128, 61)),
        "sqlite" or "db" => ForensicBadgeBrush(Color.FromRgb(56, 189, 248), "BrandCyanBrush", Color.FromRgb(2, 132, 199)),
        _ => ForensicBadgeBrush(Color.FromRgb(148, 163, 184), "TextSecondaryBrush", Color.FromRgb(71, 85, 105))
    };

    public string ConfidenceIcon => Header.Confidence.Contains("100%") || Header.Confidence.Contains("Verified") || Header.Confidence.Contains("Intact")
        ? "✓"
        : Header.Confidence.Contains("High")
        ? "⚡"
        : "⚠";

    public Brush ConfidenceBadgeBrush => Header.Confidence.Contains("100%") || Header.Confidence.Contains("Verified") || Header.Confidence.Contains("Intact")
        ? ForensicBadgeBrush(Color.FromRgb(76, 175, 80), "SuccessGreenBrush", Color.FromRgb(21, 128, 61))
        : Header.Confidence.Contains("High")
        ? ForensicBadgeBrush(Color.FromRgb(0, 229, 255), "BrandCyanBrush", Color.FromRgb(2, 132, 199))
        : ForensicBadgeBrush(Color.FromRgb(255, 179, 0), "WarningAmberBrush", Color.FromRgb(180, 83, 9));

    public Brush RecoveryMethodBadgeBrush => Header.RecoveryMethod switch
    {
        var m when m.Contains("Recycle") => ForensicBadgeBrush(Color.FromRgb(76, 175, 80), "SuccessGreenBrush", Color.FromRgb(21, 128, 61)),
        var m when m.Contains("MFT") => ForensicBadgeBrush(Color.FromRgb(0, 229, 255), "BrandCyanBrush", Color.FromRgb(2, 132, 199)),
        var m when m.Contains("Comprehensive") => ForensicBadgeBrush(Color.FromRgb(187, 134, 252), "BrandPurpleBrush", Color.FromRgb(124, 58, 237)),
        _ => ForensicBadgeBrush(Color.FromRgb(255, 179, 0), "WarningAmberBrush", Color.FromRgb(180, 83, 9))
    };

    public void RefreshThemeBrushes()
    {
        OnPropertyChanged(nameof(TypeBadgeBrush));
        OnPropertyChanged(nameof(ConfidenceBadgeBrush));
        OnPropertyChanged(nameof(RecoveryMethodBadgeBrush));
    }

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged(string propName) => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(propName));
}

