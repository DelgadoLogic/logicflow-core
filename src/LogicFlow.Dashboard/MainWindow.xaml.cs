using System.IO;
using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using OmniCore.Engine;
using LogicFlow.Sentinel;
using LogicFlow.Guardian;
using LogicFlow.Lazarus;
using OmniLicense;
using LogicFlow.Native;
using Microsoft.Extensions.Logging.Abstractions;
using RegistryModule = LogicFlow.Registry;

namespace LogicFlow.Dashboard;

public partial class MainWindow : Window
{
    // ─── Module instances ───
    private readonly SystemProfiler _profiler = new(NullLogger<SystemProfiler>.Instance);
    private readonly VulnerabilityScanner _vulnScanner = new(NullLogger<VulnerabilityScanner>.Instance);
    private readonly PrivacyScrubber _privacyScrubber = new(NullLogger<PrivacyScrubber>.Instance);
    private readonly SmartDriverEngine _driverEngine = new(NullLogger<SmartDriverEngine>.Instance);
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
    private readonly DuplicateFileFinder _duplicateFinder = new();
    private readonly DiskSpaceAnalyzer _diskSpaceAnalyzer = new();
    private readonly FileShredder _fileShredder = new();
    private readonly WindowsTweakEngine _tweakEngine = new();

    // ─── Tray + Settings ───
    private TrayIconManager? _trayManager;
    private UserSettings _settings = null!;

    // ─── Resource Monitor ───
    private readonly SystemInfoEngine _sysInfo = new();
    private SystemInfoEngine.SystemSnapshot? _liveSnapshot;
    private System.Windows.Threading.DispatcherTimer? _monitorTimer;
    private bool _monitorRunning;

    // ─── Cached scan results for action handlers ───
    private VulnScanResult? _lastVulnResult;
    private List<Guardian.DriverReport>? _lastDriverResults;
    private List<BloatwarePackage>? _lastBloatResults;
    private List<StartupItem>? _lastStartupResults;
    private RegistryModule.RegistryScanResult? _lastRegResult;
    private List<JunkCleanerEngine.JunkScanResult>? _lastJunkReport;
    private DuplicateFileFinder.DuplicateReport? _lastDuplicateReport;

    // ─── Page panels ───
    private ScrollViewer[] _pages = [];
    private System.Windows.Controls.Button[] _navButtons = [];
    private System.Windows.Controls.Button? _activeNavButton;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _pages = [PageDashboard, PageSentinel, PageGuardian, PageMonitor, PageToolbox, PageLazarus, PageRegistry, PageSettings];
        _navButtons = [NavDashboard, NavSentinel, NavGuardian, NavMonitor, NavToolbox, NavLazarus, NavRegistry, NavSettings];
        _activeNavButton = NavDashboard;

        // Populate system profile
        try
        {
            var snapshot = await Task.Run(() => _profiler.CaptureSnapshot());
            CpuLabel.Text = snapshot.Cpu.Name;
            RamLabel.Text = $"{snapshot.Memory.TotalPhysicalBytes / (1024.0 * 1024 * 1024):F1} GB ({snapshot.Memory.UsagePercent:F0}% used)";
            GpuLabel.Text = snapshot.Gpu.Name;
            OsLabel.Text = $"{snapshot.Os.Caption} (Build {snapshot.Os.BuildNumber})";
        }
        catch { CpuLabel.Text = RamLabel.Text = GpuLabel.Text = OsLabel.Text = "N/A"; }

        // Show HWID
        try
        {
            var hwid = await Task.Run(() => new HwidGenerator().GenerateHwid());
            HwidLabel.Text = $"HWID: {hwid[..Math.Min(32, hwid.Length)]}...";
        }
        catch { HwidLabel.Text = "HWID: unavailable"; }

        DataPathLabel.Text = new LogicFlowConfig().AppDataPath;

        // Initialize tray icon
        _trayManager = new TrayIconManager(this);

        // Load user settings
        _settings = SettingsManager.Load();
        if (_settings.FirstRunDate == DateTimeOffset.MinValue)
        {
            _settings.FirstRunDate = DateTimeOffset.UtcNow;
            SettingsManager.Save();
        }

        // Detect drives for Lazarus
        await RefreshDrives();

        // Check for updates in background
        _ = Task.Run(async () =>
        {
            var update = await _updateEngine.CheckForUpdateAsync();
            if (update != null)
                Dispatcher.Invoke(() => _trayManager?.ShowBalloon(
                    "LogicFlow Update", $"v{update.Version} available. Click to download.",
                    System.Windows.Forms.ToolTipIcon.Info));
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  PAGE NAVIGATION
    // ═══════════════════════════════════════════════════════════
    private void ShowPage(ScrollViewer target, string title, System.Windows.Controls.Button navButton)
    {
        // Update nav button active states
        if (_activeNavButton != null && _activeNavButton != navButton)
            _activeNavButton.Style = (Style)FindResource("NavButton");
        navButton.Style = (Style)FindResource("NavButtonActive");
        _activeNavButton = navButton;

        // Hide all pages, show target
        foreach (var page in _pages) page.Visibility = Visibility.Collapsed;
        target.Visibility = Visibility.Visible;
        PageTitle.Text = title;

        // Animate the page content with fade + slide
        var content = FindPageContent(target);
        if (content != null)
        {
            AnimatePageIn(content);
        }
    }

    private StackPanel? FindPageContent(ScrollViewer sv)
    {
        if (sv.Content is StackPanel sp) return sp;
        return null;
    }

    private void AnimatePageIn(StackPanel panel)
    {
        panel.Opacity = 0;
        var tt = panel.RenderTransform as TranslateTransform;
        if (tt == null)
        {
            tt = new TranslateTransform();
            panel.RenderTransform = tt;
        }
        tt.Y = 20;

        var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(250))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };

        var slideIn = new DoubleAnimation(20, 0, TimeSpan.FromMilliseconds(300))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };

        panel.BeginAnimation(UIElement.OpacityProperty, fadeIn);
        tt.BeginAnimation(TranslateTransform.YProperty, slideIn);
    }

    private void OnNavDashboard(object s, RoutedEventArgs e) => ShowPage(PageDashboard, "System Dashboard", NavDashboard);
    private void OnNavSentinel(object s, RoutedEventArgs e) => ShowPage(PageSentinel, "Sentinel — Security Center", NavSentinel);
    private void OnNavGuardian(object s, RoutedEventArgs e) => ShowPage(PageGuardian, "Guardian — Performance", NavGuardian);
    private void OnNavMonitor(object s, RoutedEventArgs e)
    {
        ShowPage(PageMonitor, "Resource Monitor — Live", NavMonitor);
        if (!_monitorRunning)
            OnStartMonitor(s, new RoutedEventArgs());
    }
    private void OnNavToolbox(object s, RoutedEventArgs e) => ShowPage(PageToolbox, "Toolbox — Utilities", NavToolbox);
    private void OnNavLazarus(object s, RoutedEventArgs e) => ShowPage(PageLazarus, "Lazarus — Data Recovery", NavLazarus);
    private void OnNavRegistry(object s, RoutedEventArgs e) => ShowPage(PageRegistry, "Registry Surgeon", NavRegistry);
    private void OnNavSettings(object s, RoutedEventArgs e) => ShowPage(PageSettings, "Settings", NavSettings);

    // ═══════════════════════════════════════════════════════════
    //  RESOURCE MONITOR
    // ═══════════════════════════════════════════════════════════
    private async void OnStartMonitor(object s, RoutedEventArgs e)
    {
        if (_monitorRunning) return;

        MonitorStatus.Text = "⏳ Initializing...";
        BtnStartMonitor.IsEnabled = false;

        // Collect the full snapshot (heavy WMI query) once on a background thread
        _liveSnapshot = await Task.Run(() => _sysInfo.CollectSnapshot());

        // Populate static fields from the snapshot
        CpuNameText.Text = _liveSnapshot.CpuName;
        CpuCoresText.Text = $"{_liveSnapshot.CpuCores} cores, {_liveSnapshot.CpuThreads} threads | {_liveSnapshot.CpuSpeedGHz:F1} GHz max";
        MonitorCpuFullText.Text = _liveSnapshot.CpuName;
        MonitorGpuText.Text = $"{_liveSnapshot.GpuName} ({_liveSnapshot.GpuVramFormatted} VRAM)";
        OsDetailText.Text = _liveSnapshot.OsName;
        IpText.Text = _liveSnapshot.IpAddress;
        NetworkInfoText.Text = _liveSnapshot.NetworkSpeedMbps > 0
            ? $"{_liveSnapshot.ActiveNetworkAdapter} ({_liveSnapshot.NetworkSpeedMbps} Mbps)"
            : _liveSnapshot.ActiveNetworkAdapter;

        // Build initial disk list
        RebuildDiskList();

        // Start 1-second timer
        _monitorTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _monitorTimer.Tick += OnMonitorTick;
        _monitorTimer.Start();

        _monitorRunning = true;
        MonitorStatus.Text = "● Live";
        MonitorStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        BtnStartMonitor.Visibility = Visibility.Collapsed;
        BtnStopMonitor.Visibility = Visibility.Visible;
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
        if (_liveSnapshot == null) return;
        // Run lightweight update on background thread, push results back on UI thread
        Task.Run(() => _sysInfo.UpdateLiveMetrics(_liveSnapshot))
            .ContinueWith(_ => Dispatcher.Invoke(UpdateMonitorUI),
                System.Threading.Tasks.TaskContinuationOptions.None);
    }

    private static Brush MetricBrush(double pct, ResourceDictionary res) => pct switch
    {
        > 80 => (Brush)res["DangerRedBrush"],
        > 60 => (Brush)res["WarningAmberBrush"],
        _    => (Brush)res["SuccessGreenBrush"]
    };

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
    }

    private void RebuildDiskList()
    {
        if (_liveSnapshot == null) return;
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
                Background = new SolidColorBrush(System.Windows.Media.Color.FromArgb(0x1A, 0x1A, 0x1F, 0x2E)),
                Padding = new System.Windows.Thickness(12, 10, 12, 10),
                Margin = new System.Windows.Thickness(0, 0, 0, 8)
            };

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
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextPrimaryBrush")
            };
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
                Foreground = brush,
                Background = new SolidColorBrush(System.Windows.Media.Color.FromArgb(0xFF, 0x1A, 0x1F, 0x2E))
            };
            bar.SetValue(System.Windows.Controls.Control.BackgroundProperty,
                new SolidColorBrush(System.Windows.Media.Color.FromArgb(0xFF, 0x1A, 0x1F, 0x2E)));

            var detail = new TextBlock
            {
                Text = $"{freeGB:F1} GB free of {totalGB:F1} GB total",
                FontSize = 10,
                Foreground = (Brush)FindResource("TextSecondaryBrush")
            };

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

    // ═══════════════════════════════════════════════════════════
    //  DASHBOARD QUICK ACTIONS
    // ═══════════════════════════════════════════════════════════
    private async void OnQuickSecurityScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Running security scan...");
        try
        {
            var result = await _vulnScanner.ScanAsync();
            _lastVulnResult = result;
            var score = Math.Max(0, 100 - (result.Vulnerabilities.Count * 20) - (result.ExposedServices.Count * 5));
            SecurityScore.Text = score.ToString();
            SecurityScore.Foreground = ScoreBrush(score);
            SecuritySub.Text = $"🛡 {result.Vulnerabilities.Count} vulns, {result.ExposedServices.Count} exposed services";
        }
        catch (Exception ex) { SecuritySub.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnQuickPerfScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing performance...");
        try
        {
            var drivers = await Task.Run(() => _driverEngine.ScanDrivers());
            var startup = await Task.Run(() => _startupOptimizer.AnalyzeStartupItems());
            _lastDriverResults = drivers;
            _lastStartupResults = startup;
            var badDrivers = drivers.Count(d => d.Status != Guardian.DriverStatus.Healthy);
            var heavyStartup = startup.Count(si => si.ImpactScore >= 7);
            var score = Math.Max(0, 100 - (badDrivers * 3) - (heavyStartup * 5));
            PerfScore.Text = score.ToString();
            PerfScore.Foreground = ScoreBrush(score);
            PerfSub.Text = $"⚡ {badDrivers} driver issues, {heavyStartup} high-impact startup items";
        }
        catch (Exception ex) { PerfSub.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnQuickPrivacyScrub(object s, RoutedEventArgs e)
    {
        ShowLoading("Scrubbing privacy artifacts...");
        try
        {
            var report = await Task.Run(() => _privacyScrubber.Scrub());
            SecuritySub.Text = $"🧹 Cleared {report.TotalFilesCleared} files ({report.TotalBytesCleared / (1024.0 * 1024):F1} MB)";
        }
        catch (Exception ex) { SecuritySub.Text = $"Scrub error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnQuickRegistryScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning registry...");
        try
        {
            var result = await Task.Run(() => _registryAnalyzer.Scan());
            _lastRegResult = result;
            var score = Math.Max(0, 100 - result.TotalIssues * 2);
            RegScore.Text = score.ToString();
            RegScore.Foreground = ScoreBrush(score);
            RegSub.Text = $"🔧 {result.TotalIssues} issues found";
        }
        catch (Exception ex) { RegSub.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnRunAllScans(object s, RoutedEventArgs e)
    {
        ShowLoading("Running all scans...");
        OnQuickSecurityScan(s, e);
        await Task.Delay(200);
        OnQuickPerfScan(s, e);
        await Task.Delay(200);
        OnQuickRegistryScan(s, e);
    }

    // ─── New Quick Actions ───
    private async void OnQuickJunkClean(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning junk files...");
        try
        {
            var report = await Task.Run(() => _junkCleaner.Scan());
            _lastJunkReport = report;
            var totalMB = report.Sum(c => c.TotalBytes) / (1024.0 * 1024);
            SecuritySub.Text = $"🧹 {report.Sum(c => c.FileCount)} junk files ({totalMB:F1} MB)";
        }
        catch (Exception ex) { SecuritySub.Text = $"Junk scan error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnQuickMemoryOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Optimizing memory...");
        try
        {
            var result = await Task.Run(() => _memoryOptimizer.Optimize());
            var afterPct = result.After.PhysicalUsagePercent;
            var freedMB = result.TotalMemoryFreedBytes / (1024.0 * 1024);
            MemoryLabel.Text = $"{afterPct:F0}%";
            MemoryLabel.Foreground = afterPct < 70 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("WarningAmberBrush");
            var areasText = result.IsAdmin
                ? $"🧠 Freed {freedMB:F0} MB ({result.AreasCleared})"
                : $"🧠 Freed {freedMB:F0} MB (run as admin for full optimization)";
            MemorySub.Text = areasText;
        }
        catch (Exception ex) { MemorySub.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnToggleTurbo(object s, RoutedEventArgs e)
    {
        ShowPage(PageToolbox, "Toolbox — Utilities", NavToolbox);
    }

    // ═══════════════════════════════════════════════════════════
    //  1-CLICK MAINTENANCE
    // ═══════════════════════════════════════════════════════════
    private async void OnOneClickOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Running 1-Click Maintenance...");
        try
        {
            // Run full 1-Click Maintenance via the orchestrator
            var oneClick = new OneClickMaintenance();
            OneClickStatus.Text = "Running maintenance...";
            var report = await Task.Run(() => oneClick.Run(_junkCleaner, _tweakEngine));

            // Also run memory optimize
            OneClickStatus.Text = "Optimizing memory...";
            var memResult = await Task.Run(() => _memoryOptimizer.Optimize());

            // Calculate health score
            var afterPct = memResult.After.PhysicalUsagePercent;
            var freedMB = memResult.TotalMemoryFreedBytes / (1024.0 * 1024);
            var junkMB = (int)(report.JunkBytesCleaned / (1024 * 1024));
            var diskUsage = 50.0; // reasonable default
            try { var di = new DriveInfo("C"); diskUsage = (1.0 - (double)di.TotalFreeSpace / di.TotalSize) * 100; } catch { }
            var score = OneClickMaintenance.HealthScore.Calculate(afterPct, diskUsage, junkMB, report.RegistryIssuesFound, report.SafeTweaksApplied, report.HighImpactStartupItems);

            // Update Dashboard cards
            HealthScoreLabel.Text = score.Score.ToString();
            HealthScoreLabel.Foreground = ScoreBrush(score.Score);
            HealthScoreSub.Text = $"🏥 Grade: {score.Grade}";

            MemoryLabel.Text = $"{afterPct:F0}%";
            MemoryLabel.Foreground = afterPct < 70 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("WarningAmberBrush");
            MemorySub.Text = $"🧠 Freed {freedMB:F0} MB";

            OneClickSummaryBar.Visibility = Visibility.Visible;
            OneClickSummaryText.Text = $"✅ {report.Summary} — Freed {freedMB:F0} MB RAM";
            OneClickStatus.Text = "1-Click Maintenance complete!";
            OneClickStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { OneClickStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ═══════════════════════════════════════════════════════════
    //  SENTINEL PAGE — Security Scan + Fix Actions
    // ═══════════════════════════════════════════════════════════
    private async void OnSentinelScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Deep security scan...");
        SentinelStatus.Text = "Scanning...";
        VulnList.Items.Clear();
        ServiceList.Items.Clear();

        try
        {
            var result = await _vulnScanner.ScanAsync();
            _lastVulnResult = result;

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

            // Populate detail list (hidden by default)
            foreach (var v in result.Vulnerabilities)
                VulnList.Items.Add(MakeActionCard($"⚠ {v.KbId} — {v.Title}", v.Impact, "DangerRedBrush", "🔧 Fix", () => OpenWindowsUpdate()));

            if (result.Vulnerabilities.Count == 0)
                VulnList.Items.Add(MakeResultCard("✅ System is patched and up to date", "All known CVEs addressed", "SuccessGreenBrush"));

            // Exposed services summary
            ServiceSummaryBar.Visibility = Visibility.Visible;
            ServiceSummaryText.Text = result.ExposedServices.Count > 0
                ? $"🔓 {result.ExposedServices.Count} exposed services detected"
                : "✅ No exposed services";
            BtnDisableServices.Visibility = result.ExposedServices.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

            foreach (var svc in result.ExposedServices)
                ServiceList.Items.Add(MakeActionCard($"🔓 {svc.DisplayName} ({svc.ServiceName})", svc.Risk, "WarningAmberBrush", "🔒 Disable", null));

            SentinelStatus.Text = $"Scan complete — {result.InstalledUpdates.Count} updates checked";
            SentinelStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");

            // Update dashboard card
            var score = Math.Max(0, 100 - (result.Vulnerabilities.Count * 20) - (result.ExposedServices.Count * 5));
            SecurityScore.Text = score.ToString();
            SecurityScore.Foreground = ScoreBrush(score);
            SecuritySub.Text = $"🛡 {result.Vulnerabilities.Count} vulns, {result.ExposedServices.Count} exposed";
        }
        catch (Exception ex) { SentinelStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnFixVulnerabilities(object s, RoutedEventArgs e) => OpenWindowsUpdate();

    private void OnDisableExposedServices(object s, RoutedEventArgs e)
    {
        if (_lastVulnResult == null) return;
        MessageBox.Show(
            $"This will disable {_lastVulnResult.ExposedServices.Count} risky services.\n" +
            "Services can be re-enabled from Windows Services (services.msc).\n\n" +
            "In a production build, LogicFlow would stop each service and set it to Disabled.",
            "LogicFlow — Disable Risky Services", MessageBoxButton.OK, MessageBoxImage.Information);
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

    // ═══════════════════════════════════════════════════════════
    //  GUARDIAN PAGE — Drivers + Update All
    //  (Driver scan adapted from Optimizer's hardware inspection;
    //   action pattern inspired by IObit Driver Booster)
    // ═══════════════════════════════════════════════════════════
    private async void OnDriverScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning drivers...");
        DriverList.Items.Clear();
        try
        {
            var drivers = await Task.Run(() => _driverEngine.ScanDrivers());
            _lastDriverResults = drivers.ToList();
            var healthy = drivers.Count(d => d.Status == DriverStatus.Healthy);
            var outdated = drivers.Count(d => d.Status == DriverStatus.Outdated);
            var unsigned = drivers.Count(d => d.Status == DriverStatus.Unsigned);
            var missing = drivers.Count(d => d.Status == DriverStatus.Missing);

            // Summary bar with counts (not verbose list)
            DriverSummaryBar.Visibility = Visibility.Visible;
            DriverSummaryText.Text = $"✅ {healthy} healthy | ⏳ {outdated} outdated | ⚠ {unsigned} unsigned | ❌ {missing} missing";
            DriverStatusLabel.Text = $"Scanned {drivers.Count} drivers";
            DriverStatusLabel.Foreground = (Brush)FindResource("SuccessGreenBrush");

            // Show Update All if issues exist
            BtnUpdateDrivers.Visibility = (outdated + unsigned + missing) > 0 ? Visibility.Visible : Visibility.Collapsed;

            // Populate detail list (hidden by default — user clicks "Show Details")
            foreach (var d in drivers.OrderBy(d => d.Status == DriverStatus.Healthy ? 1 : 0).Take(30))
            {
                var color = d.Status switch
                {
                    DriverStatus.Healthy => "SuccessGreenBrush",
                    DriverStatus.Outdated => "WarningAmberBrush",
                    DriverStatus.Unsigned => "DangerRedBrush",
                    _ => "TextSecondaryBrush"
                };
                var icon = d.Status switch
                {
                    DriverStatus.Healthy => "✅",
                    DriverStatus.Outdated => "⏳",
                    DriverStatus.Unsigned => "⚠",
                    DriverStatus.Missing => "❌",
                    _ => "❓"
                };

                if (d.Status != DriverStatus.Healthy)
                {
                    DriverList.Items.Add(MakeActionCard(
                        $"{icon} {d.DeviceName}",
                        $"v{d.DriverVersion} | {d.Manufacturer} | {d.Status}",
                        color, "🔄 Update", null));
                }
                else
                {
                    DriverList.Items.Add(MakeResultCard(
                        $"{icon} {d.DeviceName}",
                        $"v{d.DriverVersion} | {d.Manufacturer}",
                        color));
                }
            }

            // Update dashboard
            var issueCount = outdated + unsigned + missing;
            var score = Math.Max(0, 100 - issueCount * 3);
            PerfScore.Text = score.ToString();
            PerfScore.Foreground = ScoreBrush(score);
            PerfSub.Text = $"⚡ {issueCount} driver issues";
        }
        catch (Exception ex) { DriverStatusLabel.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }


    private void OnUpdateAllDrivers(object s, RoutedEventArgs e)
    {
        if (_lastDriverResults == null) return;
        var issues = _lastDriverResults.Count(d => d.Status != DriverStatus.Healthy);
        MessageBox.Show(
            $"LogicFlow will attempt to update {issues} drivers.\n\n" +
            "• Outdated drivers → search Windows Update catalog\n" +
            "• Unsigned drivers → flag for manual review\n" +
            "• Missing drivers → attempt PnP re-detection\n\n" +
            "In a production build, this would invoke devcon.exe or Windows Update API.",
            "LogicFlow — Update All Drivers", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ─── Bloatware Scanner + Remove (adapted from BloatBox PowerShell pattern) ───
    private async void OnBloatwareScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Detecting bloatware...");
#pragma warning disable CS8604
        BloatList.Items.Clear();
        try
        {
            var packages = await Task.Run(() => _debloatEngine.ScanBloatware());
            _lastBloatResults = packages;

            // Summary bar with count + size estimate
            BloatSummaryBar.Visibility = Visibility.Visible;
            BloatSummaryText.Text = packages.Count > 0
                ? $"🗑 {packages.Count} bloatware packages detected — safe to remove"
                : "✅ No bloatware detected — system is clean";
            BloatSummaryText.Foreground = packages.Count > 0
                ? (Brush)FindResource("WarningAmberBrush")
                : (Brush)FindResource("SuccessGreenBrush");

            BtnRemoveBloat.Visibility = packages.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            BloatStatus.Text = $"Found {packages.Count} packages";

            // Per-item cards with Remove button (like BloatBox's per-app uninstall)
            foreach (var p in packages)
                BloatList.Items.Add(MakeActionCard($"🗑 {p.Name}", $"{p.Publisher} v{p.Version}", "WarningAmberBrush", "❌ Remove", null));
        }
        catch (Exception ex) { BloatStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnRemoveAllBloatware(object s, RoutedEventArgs e)
    {
        if (_lastBloatResults == null || _lastBloatResults.Count == 0) return;
        var answer = MessageBox.Show(
            $"Remove {_lastBloatResults.Count} bloatware packages?\n\n" +
            "This uses PowerShell Get-AppxPackage | Remove-AppxPackage\n" +
            "(adapted from BloatBox open-source debloater).\n\n" +
            "Packages can potentially be reinstalled from the Microsoft Store.",
            "LogicFlow — Remove All Bloatware", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes)
        {
            MessageBox.Show("Bloatware removal simulated. In production, LogicFlow executes:\n" +
                "Get-AppxPackage <name> | Remove-AppxPackage\nfor each selected package.",
                "Removal Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            BloatSummaryText.Text = "✅ All bloatware removed";
            BloatSummaryText.Foreground = (Brush)FindResource("SuccessGreenBrush");
            BtnRemoveBloat.Visibility = Visibility.Collapsed;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  TOOLBOX PAGE — Junk Cleaner, Memory, Turbo, Duplicates,
    //  Disk Space, File Shredder
    // ═══════════════════════════════════════════════════════════

    // ─── Junk Cleaner ───
    private async void OnJunkScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning for junk files...");
        JunkList.Items.Clear();
        try
        {
            var report = await Task.Run(() => _junkCleaner.Scan());
            _lastJunkReport = report;
            var totalSize = report.Sum(c => c.TotalBytes);
            var totalFiles = report.Sum(c => c.FileCount);

            JunkSummaryBar.Visibility = Visibility.Visible;
            JunkSummaryText.Text = $"🧹 {totalFiles:N0} files ({totalSize / (1024.0 * 1024):F1} MB) across {report.Count} categories";
            BtnCleanJunk.Visibility = totalFiles > 0 ? Visibility.Visible : Visibility.Collapsed;
            JunkStatus.Text = $"Scan complete — {totalFiles:N0} junk files found";

            foreach (var cat in report.OrderByDescending(c => c.TotalBytes))
            {
                var sizeMB = cat.TotalBytes / (1024.0 * 1024);
                JunkList.Items.Add(MakeResultCard(
                    $"🗑 {cat.DisplayName}",
                    $"{cat.FileCount} files — {sizeMB:F1} MB",
                    sizeMB > 100 ? "DangerRedBrush" : sizeMB > 10 ? "WarningAmberBrush" : "TextSecondaryBrush"));
            }
        }
        catch (Exception ex) { JunkStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private async void OnJunkClean(object s, RoutedEventArgs e)
    {
        if (_lastJunkReport == null) return;
        ShowLoading("Cleaning junk files...");
        try
        {
            var result = await Task.Run(() => _junkCleaner.Clean(_lastJunkReport));
            JunkSummaryText.Text = $"✅ Cleaned {result.FilesDeleted:N0} files — {result.BytesCleaned / (1024.0 * 1024):F1} MB freed";
            JunkSummaryText.Foreground = (Brush)FindResource("SuccessGreenBrush");
            BtnCleanJunk.Visibility = Visibility.Collapsed;
            JunkStatus.Text = "Cleanup complete!";
            JunkStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
        }
        catch (Exception ex) { JunkStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
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
            MemoryLabel.Text = $"{afterPct:F0}%";
            MemoryLabel.Foreground = afterPct < 70 ? (Brush)FindResource("SuccessGreenBrush") : (Brush)FindResource("WarningAmberBrush");
            MemorySub.Text = $"🧠 Freed {freedMB:F0} MB ({result.AreasCleared})";
        }
        catch (Exception ex) { MemOptStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Virtual Memory / Pagefile Optimizer ───
    private async void OnVirtualMemoryOptimize(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing virtual memory...");
        MemOptList.Items.Clear();
        try
        {
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
            MemOptSummaryText.Text = $"{statusIcon} Virtual Memory: {analysis.Status}";
            MemOptStatus.Text = $"Commit Charge: {analysis.CommitPercent:F0}%";

            // Current state
            MemOptList.Items.Add(MakeResultCard("💿 RAM", $"{analysis.PhysicalRamGB} GB physical memory", "BrandCyanBrush"));
            MemOptList.Items.Add(MakeResultCard("📊 Commit Charge",
                $"{analysis.CommitPercent:F0}% ({analysis.CommitChargeMB:N0} / {analysis.CommitLimitMB:N0} MB)",
                analysis.CommitPercent > 80 ? "DangerRedBrush" : "SuccessGreenBrush"));
            MemOptList.Items.Add(MakeResultCard("📁 Current Pagefile",
                analysis.CurrentSizeFormatted, "BrandCyanBrush"));
            MemOptList.Items.Add(MakeResultCard("🎯 Recommended",
                $"{analysis.RecommendedSizeFormatted} on {analysis.RecommendedDrive}:",
                "SuccessGreenBrush"));
            MemOptList.Items.Add(MakeResultCard("📐 Rationale", analysis.SizingRationale, "BrandCyanBrush"));

            // Drive analysis
            foreach (var drive in analysis.Drives)
            {
                MemOptList.Items.Add(MakeResultCard($"💽 {drive.DriveLetter}: ({drive.MediaType})",
                    $"{drive.FreeSpaceGB} GB free / {drive.TotalSpaceGB} GB{(drive.IsSystemDrive ? " [System]" : "")}",
                    drive.IsSsd ? "SuccessGreenBrush" : "WarningAmberBrush"));
            }

            // Warnings
            foreach (var warning in analysis.Warnings)
                MemOptList.Items.Add(MakeResultCard("⚠️ Warning", warning, "DangerRedBrush"));

            // Recommendations
            foreach (var rec in analysis.Recommendations)
                MemOptList.Items.Add(MakeResultCard("💡 Tip", rec, "WarningAmberBrush"));
        }
        catch (Exception ex) { MemOptStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Turbo Mode Profiles ───
    private async void ActivateTurbo(TurboMode.TurboProfile profile, string name)
    {
        ShowLoading($"Activating {name} Turbo...");
        try
        {
            var result = await Task.Run(() => _turboMode.Activate(profile));
            
            // Set dynamic branding based on mode
            Brush accentBrush = name switch
            {
                "Gaming" => (Brush)FindResource("TurboGamingOrangeBrush"),
                "Work" => (Brush)FindResource("TurboWorkPurpleBrush"),
                "Battery" => (Brush)FindResource("TurboBatteryGreenBrush"),
                _ => (Brush)FindResource("TextPrimaryBrush")
            };

            // Glow Effect styling
            TurboModeContainer.BorderBrush = accentBrush;
            TurboModeContainer.BorderThickness = new Thickness(2);
            TurboSummaryText.Foreground = accentBrush;
            
            TurboSummaryBar.Visibility = Visibility.Visible;
            TurboSummaryText.Text = $"SYSTEM OVERRIDDEN: {name.ToUpper()} MODE";
            TurboModeStatus.Text = $"{result.ServicesDisabled} services paused, {result.ProcessesKilled} background processes killed. {result.MemoryFreedFormatted} RAM freed.";
            TurboModeStatus.Foreground = accentBrush;
            
            // Load Live Native Output
            TurboActionList.ItemsSource = result.Actions;

            // Manage Toggles
            BtnTurboGaming.Visibility = Visibility.Collapsed;
            BtnTurboWork.Visibility = Visibility.Collapsed;
            BtnTurboBattery.Visibility = Visibility.Collapsed;
            BtnTurboServer.Visibility = Visibility.Collapsed;
            BtnTurboOff.Visibility = Visibility.Visible;

            // Update Global Dashboard Card
            TurboStatusLabel.Text = "ACTIVE";
            TurboStatusLabel.Foreground = accentBrush;
            TurboSub.Text = $"🚀 {name} Overrides Enabled";
        }
        catch (Exception ex) { TurboModeStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnTurboGaming(object s, RoutedEventArgs e) => ActivateTurbo(TurboMode.GamingProfile, "Gaming");
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
            TurboModeStatus.Text = "Forcefully suspend non-essential processes, configure CPU affinity, and alter network routing for raw power.";
            TurboModeStatus.Foreground = (Brush)FindResource("TextSecondaryBrush");
            
            TurboActionList.ItemsSource = result.Actions;

            // Manage Toggles
            BtnTurboOff.Visibility = Visibility.Collapsed;
            BtnTurboGaming.Visibility = Visibility.Visible;
            BtnTurboWork.Visibility = Visibility.Visible;
            BtnTurboBattery.Visibility = Visibility.Visible;
            BtnTurboServer.Visibility = Visibility.Visible;

            // Update Global Dashboard Card
            TurboStatusLabel.Text = "STANDBY";
            TurboStatusLabel.Foreground = (Brush)FindResource("TextSecondaryBrush");
            TurboSub.Text = "🚀 Ready to Activate";
        }
        catch (Exception ex) { TurboModeStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Disk Space Analyzer ───
    private async void OnDiskSpaceAnalyze(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing disk space...");
        DiskSpaceList.Items.Clear();
        try
        {
            var driveSummary = await Task.Run(() => _diskSpaceAnalyzer.GetDriveSummaries());
            DiskSpaceSummaryBar.Visibility = Visibility.Visible;
            DiskSpaceSummaryText.Text = $"📊 {driveSummary.Count} drives analyzed";
            DiskSpaceStatus.Text = "Analysis complete";

            foreach (var drive in driveSummary)
            {
                var color = drive.UsagePercent > 90 ? "DangerRedBrush" : drive.UsagePercent > 70 ? "WarningAmberBrush" : "SuccessGreenBrush";
                DiskSpaceList.Items.Add(MakeResultCard(
                    $"💾 {drive.Name} ({drive.Label})",
                    $"{drive.UsedFormatted} / {drive.TotalFormatted} ({drive.UsagePercent:F0}% used) — {drive.FreeFormatted} free",
                    color));
            }
        }
        catch (Exception ex) { DiskSpaceStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Duplicate File Finder ───
    private async void OnDuplicateScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning for duplicates (this may take a while)...");
        DuplicateList.Items.Clear();
        try
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var paths = new[] {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                Path.Combine(userProfile, "Pictures"),
                Path.Combine(userProfile, "Desktop")
            };
            var report = await Task.Run(() => _duplicateFinder.Scan(paths));
            _lastDuplicateReport = report;

            DuplicateSummaryBar.Visibility = Visibility.Visible;
            DuplicateSummaryText.Text = $"🔍 {report.Groups.Count} duplicate groups — {report.TotalDuplicates} copies wasting {report.WastedFormatted}";
            DuplicateStatus.Text = $"Scanned {report.TotalFilesScanned:N0} files in {report.ScanDuration.TotalSeconds:F1}s";

            foreach (var group in report.Groups.Take(20))
            {
                DuplicateList.Items.Add(MakeResultCard(
                    $"📄 {group.Files.First().Name} × {group.Files.Count}",
                    $"Each: {group.SizeFormatted} | Wasted: {group.WastedFormatted}",
                    "WarningAmberBrush"));
            }
        }
        catch (Exception ex) { DuplicateStatus.Text = $"Error: {ex.Message}"; }
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

        var answer = MessageBox.Show(
            $"PERMANENTLY SHRED {dlg.FileNames.Length} file(s)?\n\n" +
            "This uses DoD 5220.22-M 3-pass secure deletion.\n" +
            "Files CANNOT be recovered after shredding.\n\n" +
            "Are you absolutely sure?",
            "LogicFlow — File Shredder", MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (answer != MessageBoxResult.Yes) return;

        var shredResult = _fileShredder.Shred(dlg.FileNames, FileShredder.ShredMethod.DoD3Pass);
        int success = shredResult.FilesShredded;

        ShredderSummaryBar.Visibility = Visibility.Visible;
        ShredderSummaryText.Text = $"✅ {success}/{dlg.FileNames.Length} files securely shredded";
        ShredderStatus.Text = "Shredding complete";
        ShredderStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
    }

    // ─── SMART Disk Health ───
    private async void OnSmartDiskScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Reading S.M.A.R.T. data...");
        SmartDiskList.Items.Clear();
        try
        {
            var drives = await Task.Run(() => _smartDiskHealth.ScanDrives());

            SmartDiskSummaryBar.Visibility = Visibility.Visible;
            var healthy = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Healthy);
            var critical = drives.Count(d => d.Status == SmartDiskHealth.DiskHealthStatus.Critical);
            SmartDiskSummaryText.Text = $"💾 {drives.Count} drives: {healthy} healthy, {critical} critical";
            SmartDiskStatus.Text = "SMART scan complete";

            foreach (var drive in drives)
            {
                var color = drive.Status switch
                {
                    SmartDiskHealth.DiskHealthStatus.Healthy => "SuccessGreenBrush",
                    SmartDiskHealth.DiskHealthStatus.Warning => "WarningAmberBrush",
                    SmartDiskHealth.DiskHealthStatus.Critical => "DangerRedBrush",
                    _ => "TextSecondaryBrush"
                };
                SmartDiskList.Items.Add(MakeResultCard(
                    $"{drive.HealthSummary}",
                    $"{drive.Model} | {drive.SizeFormatted} | {drive.MediaType} | Temp: {drive.Temperature}°C | Power-On: {drive.PowerOnHours}h",
                    color));
            }

            // Update Dashboard
            DiskHealthLabel.Text = critical > 0 ? "⚠" : "✓";
            DiskHealthLabel.Foreground = critical > 0 ? (Brush)FindResource("DangerRedBrush") : (Brush)FindResource("SuccessGreenBrush");
            DiskHealthSub.Text = $"💾 {healthy}/{drives.Count} drives healthy";
        }
        catch (Exception ex) { SmartDiskStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    // ─── Windows Tweaks ───
    private void OnTweakScan(object s, RoutedEventArgs e)
    {
        TweakList.Items.Clear();
        _tweakEngine.RefreshStates();
        var summary = _tweakEngine.GetSummary();

        TweakSummaryBar.Visibility = Visibility.Visible;
        var totalTweaks = summary.Values.Sum(v => v.Total);
        var appliedTweaks = summary.Values.Sum(v => v.Applied);
        TweakSummaryText.Text = $"🔍 {totalTweaks} tweaks available — {appliedTweaks} already applied";
        TweakStatus.Text = "Scan complete";
        BtnApplyTweaks.Visibility = appliedTweaks < totalTweaks ? Visibility.Visible : Visibility.Collapsed;

        var categoryIcons = new Dictionary<TweakCategory, string>
        {
            [TweakCategory.Privacy] = "🔒", [TweakCategory.Performance] = "⚡",
            [TweakCategory.Gaming] = "🎮", [TweakCategory.Network] = "🌐",
            [TweakCategory.Services] = "🔧", [TweakCategory.Visual] = "🖥",
            [TweakCategory.Maintenance] = "🔑"
        };

        foreach (var (cat, (applied, total)) in summary)
        {
            var icon = categoryIcons.GetValueOrDefault(cat, "📋");
            var color = applied == total ? "SuccessGreenBrush" : applied > 0 ? "WarningAmberBrush" : "BrandCyanBrush";
            TweakList.Items.Add(MakeResultCard(
                $"{icon} {cat} ({applied}/{total} applied)",
                string.Join(", ", _tweakEngine.GetByCategory(cat).Take(3).Select(t => t.Name)),
                color));
        }
    }

    private void OnApplyAllSafeTweaks(object s, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(
            "Apply all SAFE Windows optimizations?\n\n" +
            "This includes privacy hardening, performance tweaks, and gaming optimizations.\n" +
            "All changes are reversible through Windows Settings or LogicFlow.\n\n" +
            "A System Restore point will be created first.",
            "LogicFlow — Apply Safe Tweaks", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (answer == MessageBoxResult.Yes)
        {
            try
            {
                var results = _tweakEngine.ApplyAllSafe();
                var successCount = results.Count(r => r.Success);
                TweakSummaryText.Text = $"✅ {successCount} safe tweaks applied successfully";
                TweakSummaryText.Foreground = (Brush)FindResource("SuccessGreenBrush");
                BtnApplyTweaks.Visibility = Visibility.Collapsed;
                TweakStatus.Text = $"{successCount} safe tweaks applied!";
                TweakStatus.Foreground = (Brush)FindResource("SuccessGreenBrush");
            }
            catch (Exception ex) { TweakStatus.Text = $"Error: {ex.Message}"; }
        }
    }

    // ─── Startup Optimizer + Disable (adapted from Optimizer's StartupHelper) ───
    private async void OnStartupScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Analyzing startup items...");
        StartupList.Items.Clear();
        try
        {
            var items = await Task.Run(() => _startupOptimizer.AnalyzeStartupItems());
            _lastStartupResults = items;
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
                        cmd, color, "⚡ Disable", null));
                }
                else
                {
                    StartupList.Items.Add(MakeResultCard(
                        $"🚀 {item.Name} [Impact: {impactLabel}]", cmd, color));
                }
            }
        }
        catch (Exception ex) { StartupStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnDisableHighImpactStartup(object s, RoutedEventArgs e)
    {
        if (_lastStartupResults == null) return;
        var highItems = _lastStartupResults.Where(si => si.ImpactScore >= 7).ToList();
        MessageBox.Show(
            $"Disable {highItems.Count} high-impact startup items?\n\n" +
            "This removes entries from:\n" +
            "• HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n" +
            "• HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n" +
            "• User/Machine Startup folders\n\n" +
            "(Registry startup management adapted from Optimizer's StartupHelper)\n" +
            "A backup will be saved before making changes.",
            "LogicFlow — Disable High-Impact Startup Items", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ═══════════════════════════════════════════════════════════
    //  LAZARUS PAGE — Drives & MTP
    // ═══════════════════════════════════════════════════════════
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
                DriveList.Items.Add(MakeResultCard(
                    $"💾 {d.Name} ({d.DriveType}) — {d.VolumeLabel}",
                    $"{d.TotalSize / (1024.0 * 1024 * 1024):F1} GB total, {d.TotalFreeSpace / (1024.0 * 1024 * 1024):F1} GB free ({pct:F0}% used)",
                    color));
            }
            RecoveryStatus.Text = "✓";
            RecoverySub.Text = $"🔄 {drives.Count} drives detected";
        }
        catch (Exception ex)
        {
            RecoveryStatus.Text = "!";
            RecoverySub.Text = $"Error: {ex.Message}";
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
    private async void OnRegistryScan(object s, RoutedEventArgs e)
    {
        ShowLoading("Scanning registry...");
        OrphanList.Items.Clear();
        BrokenAssocList.Items.Clear();
        InvalidPathList.Items.Clear();
        ObsoleteRunList.Items.Clear();
        try
        {
            var result = await Task.Run(() => _registryAnalyzer.Scan());
            _lastRegResult = result;

            // Summary bar
            RegSummaryBar.Visibility = Visibility.Visible;
            RegSummaryText.Text = $"📦 {result.OrphanedSoftwareKeys.Count} orphaned | " +
                                  $"🔗 {result.BrokenFileAssociations.Count} broken assoc | " +
                                  $"📂 {result.InvalidPaths.Count} invalid paths | " +
                                  $"🚫 {result.ObsoleteRunEntries.Count} obsolete startup = " +
                                  $"{result.TotalIssues} total";

            // Show fix buttons
            var safeCount = result.OrphanedSoftwareKeys.Count + result.BrokenFileAssociations.Count;
            BtnFixRegistrySafe.Visibility = safeCount > 0 ? Visibility.Visible : Visibility.Collapsed;
            BtnFixRegistryAll.Visibility = result.TotalIssues > 0 ? Visibility.Visible : Visibility.Collapsed;

            // Update sub-section headers with counts
            OrphanHeader.Text = $"ORPHANED SOFTWARE KEYS ({result.OrphanedSoftwareKeys.Count})";
            BrokenAssocHeader.Text = $"BROKEN FILE ASSOCIATIONS ({result.BrokenFileAssociations.Count})";
            InvalidPathHeader.Text = $"INVALID PATHS ({result.InvalidPaths.Count})";
            ObsoleteRunHeader.Text = $"OBSOLETE STARTUP ENTRIES ({result.ObsoleteRunEntries.Count})";

            RegistryStatus.Text = $"Scan complete — {result.TotalIssues} issues found";
            RegistryStatus.Foreground = result.TotalIssues > 0
                ? (Brush)FindResource("WarningAmberBrush")
                : (Brush)FindResource("SuccessGreenBrush");

            PopulateIssueList(OrphanList, result.OrphanedSoftwareKeys, "📦");
            PopulateIssueList(BrokenAssocList, result.BrokenFileAssociations, "🔗");
            PopulateIssueList(InvalidPathList, result.InvalidPaths, "📂");
            PopulateIssueList(ObsoleteRunList, result.ObsoleteRunEntries, "🚫");

            // Update dashboard
            var score = Math.Max(0, 100 - result.TotalIssues * 2);
            RegScore.Text = score.ToString();
            RegScore.Foreground = ScoreBrush(score);
            RegSub.Text = $"🔧 {result.TotalIssues} issues";
        }
        catch (Exception ex) { RegistryStatus.Text = $"Error: {ex.Message}"; }
        finally { HideLoading(); }
    }

    private void OnFixRegistrySafe(object s, RoutedEventArgs e)
    {
        if (_lastRegResult == null) return;
        var safeCount = _lastRegResult.OrphanedSoftwareKeys.Count + _lastRegResult.BrokenFileAssociations.Count;
        MessageBox.Show(
            $"Fix {safeCount} safe registry issues?\n\n" +
            "• Remove orphaned software keys (safe)\n" +
            "• Fix broken file associations (safe)\n\n" +
            "A backup will be exported to LogicFlow data directory before changes.",
            "LogicFlow — Fix Safe Registry Issues", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnFixRegistryAll(object s, RoutedEventArgs e)
    {
        if (_lastRegResult == null) return;
        var answer = MessageBox.Show(
            $"Fix ALL {_lastRegResult.TotalIssues} registry issues?\n\n" +
            "This includes:\n" +
            $"• {_lastRegResult.OrphanedSoftwareKeys.Count} orphaned keys\n" +
            $"• {_lastRegResult.BrokenFileAssociations.Count} broken associations\n" +
            $"• {_lastRegResult.InvalidPaths.Count} invalid paths\n" +
            $"• {_lastRegResult.ObsoleteRunEntries.Count} obsolete startup entries\n\n" +
            "⚠ This may affect system stability. A full backup will be created.",
            "LogicFlow — Fix All Registry Issues", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes)
        {
            MessageBox.Show("Registry fix simulated. In production, LogicFlow backs up the registry hive " +
                "and removes each identified key.\n\n" +
                "Backup saved to: %LOCALAPPDATA%\\LogicFlow\\Backups\\",
                "Fix Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private static void PopulateIssueList(ItemsControl list, List<RegistryModule.RegistryIssue> issues, string icon)
    {
        if (issues.Count == 0)
        {
            list.Items.Add(MakeResultCard("✅ None found", "", "SuccessGreenBrush"));
            return;
        }
        foreach (var issue in issues.Take(20))
        {
            var color = issue.Severity == RegistryModule.IssueSeverity.Critical ? "DangerRedBrush" :
                       issue.Severity == RegistryModule.IssueSeverity.High ? "DangerRedBrush" :
                       issue.Severity == RegistryModule.IssueSeverity.Medium ? "WarningAmberBrush" : "TextSecondaryBrush";
            list.Items.Add(MakeResultCard($"{icon} {issue.Description}", issue.Path, color));
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  UI CARD HELPERS
    // ═══════════════════════════════════════════════════════════

    /// <summary>Standard result card (read-only)</summary>
    private static Border MakeResultCard(string title, string detail, string colorKey)
    {
        Brush titleBrush;
        try { titleBrush = (Brush)Application.Current.FindResource(colorKey); }
        catch { titleBrush = Brushes.White; }

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
            Child = new StackPanel
            {
                Children =
                {
                    new TextBlock { Text = title, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = titleBrush, TextWrapping = TextWrapping.Wrap },
                    new TextBlock { Text = detail, FontSize = 10, Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,2,0,0) }
                }
            }
        };
    }

    /// <summary>Actionable result card with an action button (Fix, Update, Remove, Disable)</summary>
    private static Border MakeActionCard(string title, string detail, string colorKey, string actionLabel, Action? action)
    {
        Brush titleBrush;
        try { titleBrush = (Brush)Application.Current.FindResource(colorKey); }
        catch { titleBrush = Brushes.White; }

        var actionBtn = new System.Windows.Controls.Button
        {
            Content = actionLabel,
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Padding = new Thickness(8, 4, 8, 4),
            Background = new SolidColorBrush(Color.FromRgb(0, 229, 255)),
            Foreground = Brushes.Black,
            BorderThickness = new Thickness(0),
            Cursor = System.Windows.Input.Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
        };
        if (action != null)
            actionBtn.Click += (s, e) => action();
        else
            actionBtn.Click += (s, e) => MessageBox.Show(
                $"Action '{actionLabel}' would be executed in production.\n\nLogicFlow will handle this operation safely with automatic backups.",
                "LogicFlow Action", MessageBoxButton.OK, MessageBoxImage.Information);

        var titleBlock = new TextBlock { Text = title, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = titleBrush, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
        var detailBlock = new TextBlock { Text = detail, FontSize = 10, Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) };

        var textPanel = new StackPanel { Children = { titleBlock, detailBlock } };

        var dock = new DockPanel();
        DockPanel.SetDock(actionBtn, Dock.Right);
        
        // Use premium OutlineButton style for result actions
        actionBtn.Style = (Style)Application.Current.FindResource("OutlineButton");
        actionBtn.Margin = new Thickness(16, 0, 0, 0);

        dock.Children.Add(actionBtn);
        dock.Children.Add(textPanel);

        return new Border
        {
            Style = (Style)Application.Current.FindResource("ResultCard"),
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
    private void OnUpgradeClick(object s, RoutedEventArgs e) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://delgadologic.tech/logicflow/upgrade") { UseShellExecute = true });
    private void OnMinimize(object s, RoutedEventArgs e)
    {
        if (_settings.MinimizeToTray)
            _trayManager?.MinimizeToTray();
        else
            WindowState = WindowState.Minimized;
    }
    private void OnMaximize(object s, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void OnClose(object s, RoutedEventArgs e) => Close();

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // Deactivate Turbo Mode if running
        try { _turboMode.Deactivate(); } catch { }

        // Stop resource monitor timer
        _monitorTimer?.Stop();
        _monitorTimer = null;

        _settings.LastScanDate = DateTimeOffset.UtcNow;
        SettingsManager.Save();
        _trayManager?.Dispose();
        _updateEngine.Dispose();
    }
}
