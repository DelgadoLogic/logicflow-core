// LogicFlow.Dashboard — System Tray Integration
// Delgado Creative Enterprises LLC d/b/a DelgadoLogic
// NotifyIcon, context menu, minimize-to-tray, balloon notifications

using System.Drawing;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using LogicFlow.Guardian;

namespace LogicFlow.Dashboard;

/// <summary>
/// Manages the system tray icon for LogicFlow.
/// Provides context menu with quick actions, balloon notifications, and minimize-to-tray.
/// </summary>
public sealed class TrayIconManager : IDisposable
{
    private readonly NotifyIcon _trayIcon;
    private readonly MainWindow _mainWindow;
    private bool _disposed;

    public TrayIconManager(MainWindow mainWindow)
    {
        _mainWindow = mainWindow;

        _trayIcon = new NotifyIcon
        {
            Text = "LogicFlow — Windows Cleanup & Security",
            Icon = LoadTrayIcon(),
            ContextMenuStrip = BuildContextMenu(),
            Visible = true,
        };

        _trayIcon.Click += (_, e) =>
        {
            if (e is MouseEventArgs me && me.Button == MouseButtons.Left)
            {
                RestoreWindow();
            }
        };
        _trayIcon.DoubleClick += (_, _) => RestoreWindow();
        _trayIcon.BalloonTipClicked += (_, _) => RestoreWindow();
    }

    /// <summary>Tray icon state variants (all derived from the crystal shield master mark).</summary>
    public enum TrayState { Protected, Scanning, Attention }

    /// <summary>Switches the tray icon to the protected / scanning / attention variant.</summary>
    public void SetState(TrayState state)
    {
        if (_disposed) return;
        var file = state switch { TrayState.Scanning => "tray_scanning.ico", TrayState.Attention => "tray_attention.ico", _ => "tray_protected.ico" };
        var icon = LoadTrayIcon(file);
        var old = _trayIcon.Icon;
        _trayIcon.Icon = icon;
        if (old is not null && !ReferenceEquals(old, SystemIcons.Application)) old.Dispose();
    }

    private static Icon LoadTrayIcon(string fileName = "tray_protected.ico")
    {
        // 1. Try loading from WPF pack application resource stream
        try
        {
            var uri = new Uri($"pack://application:,,,/LogicFlow;component/Assets/Icons/{fileName}", UriKind.Absolute);
            var streamInfo = System.Windows.Application.GetResourceStream(uri);
            if (streamInfo?.Stream != null)
            {
                using var s = streamInfo.Stream;
                return new Icon(s, SystemInformation.SmallIconSize);
            }
        }
        catch { }

        // 2. Try filesystem candidate locations
        var candidates = new[]
        {
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Icons", fileName),
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Icons", "LogicFlow.ico"),
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LogicFlow.ico"),
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Icons", "logicflow_logo.ico"),
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Assets", "Icons", "LogicFlow.ico"),
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "Assets", "Icons", "LogicFlow.ico")
        };

        foreach (var path in candidates)
        {
            try
            {
                if (System.IO.File.Exists(path))
                    return new Icon(path, SystemInformation.SmallIconSize);
            }
            catch { }
        }

        // 3. Extract embedded icon from current process executable
        try
        {
            var procPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(procPath))
            {
                using var proc = System.Diagnostics.Process.GetCurrentProcess();
                procPath = proc.MainModule?.FileName;
            }
            if (!string.IsNullOrEmpty(procPath) && System.IO.File.Exists(procPath))
            {
                var assoc = Icon.ExtractAssociatedIcon(procPath);
                if (assoc != null) return new Icon(assoc, SystemInformation.SmallIconSize);
            }
        }
        catch { }

        // 4. Extract from entry assembly location
        try
        {
            var loc = System.Reflection.Assembly.GetEntryAssembly()?.Location;
            if (!string.IsNullOrEmpty(loc) && System.IO.File.Exists(loc))
            {
                var assoc = Icon.ExtractAssociatedIcon(loc);
                if (assoc != null) return new Icon(assoc, SystemInformation.SmallIconSize);
            }
        }
        catch { }

        return SystemIcons.Application;
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip
        {
            Renderer = new DarkMenuRenderer(),
            ShowImageMargin = false,
            ShowCheckMargin = true,
            BackColor = System.Drawing.Color.FromArgb(13, 17, 23),
            ForeColor = System.Drawing.Color.FromArgb(226, 232, 240),
            Font = new Font("Segoe UI", 9F)
        };

        var titleLabel = new ToolStripLabel("⚡ LogicFlow v1.0.0")
        {
            ForeColor = System.Drawing.Color.FromArgb(0, 229, 255),
            Font = new Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold)
        };
        menu.Items.Add(titleLabel);
        menu.Items.Add(new ToolStripSeparator());

        var openItem = new ToolStripMenuItem("🏠 Open Dashboard");
        openItem.Click += (_, _) => RestoreWindow();
        menu.Items.Add(openItem);

        var quickClean = new ToolStripMenuItem("🧹 Quick 1-Click Clean");
        quickClean.Click += (_, _) => OnQuickCleanFromTray();
        menu.Items.Add(quickClean);

        var turboToggle = new ToolStripMenuItem("🚀 Toggle Turbo / Boost");
        turboToggle.Click += async (_, _) => await OnToggleTurboFromTray(turboToggle);
        menu.Items.Add(turboToggle);

        menu.Items.Add(new ToolStripSeparator());

        var quickScan = new ToolStripMenuItem("📊 Quick Full Scan");
        quickScan.Click += (_, _) => OnQuickScanFromTray();
        menu.Items.Add(quickScan);

        var secScan = new ToolStripMenuItem("🛡 Security Scan");
        secScan.Click += (_, _) => OnScanFromTray("security");
        menu.Items.Add(secScan);

        var perfScan = new ToolStripMenuItem("⚡ Performance Scan");
        perfScan.Click += (_, _) => OnScanFromTray("performance");
        menu.Items.Add(perfScan);

        var regScan = new ToolStripMenuItem("🔧 Registry Scan");
        regScan.Click += (_, _) => OnScanFromTray("registry");
        menu.Items.Add(regScan);

        menu.Opening += (_, _) =>
        {
            bool isTurbo = _mainWindow.IsTurboModeActive;
            turboToggle.Checked = isTurbo;
            turboToggle.Text = isTurbo ? "🚀 Turbo Mode: ACTIVE (Boost ON)" : "🚀 Toggle Turbo / Boost";
        };

        menu.Items.Add(new ToolStripSeparator());

        var settings = new ToolStripMenuItem("⚙ Settings");
        settings.Click += (_, _) =>
        {
            RestoreWindow();
            _mainWindow.OpenSettingsPage();
        };
        menu.Items.Add(settings);

        menu.Items.Add(new ToolStripSeparator());

        var exitItem = new ToolStripMenuItem("✕ Exit LogicFlow");
        exitItem.Click += (_, _) => ExitApplication();
        menu.Items.Add(exitItem);

        return menu;
    }

    public const int MaxNotifyIconTooltipLength = 63;

    public static string FormatSafeTooltip(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "LogicFlow";
        var normalized = text.Trim();
        return normalized.Length <= MaxNotifyIconTooltipLength
            ? normalized
            : normalized[..(MaxNotifyIconTooltipLength - 1)] + "…";
    }

    public void SetTooltipSafe(string? text)
    {
        if (_disposed) return;
        try
        {
            _trayIcon.Text = FormatSafeTooltip(text);
        }
        catch { }
    }

    /// <summary>
    /// Minimizes the main window to the system tray.
    /// </summary>
    public void MinimizeToTray(bool isWindowClose = false)
    {
        _mainWindow.WindowState = WindowState.Minimized;
        _mainWindow.ShowInTaskbar = false;
        _mainWindow.Hide();

        var settings = SettingsManager.Load();
        if (isWindowClose && !settings.FirstTrayNoticeShown)
        {
            settings.FirstTrayNoticeShown = true;
            try { SettingsManager.Save(); } catch { }
            ShowBalloon(
                "LogicFlow is still running in the tray",
                "Closing the window keeps LogicFlow accessible here. Right-click the tray icon to Exit completely, or change this in Settings.",
                ToolTipIcon.Info,
                4000);
        }
        else if (settings.ShowNotifications && !isWindowClose)
        {
            ShowBalloon("LogicFlow", "LogicFlow is running in the background. Click the system tray icon to restore.", ToolTipIcon.Info);
        }
    }

    /// <summary>
    /// Restores the main window from the system tray.
    /// </summary>
    public void RestoreWindow()
    {
        _mainWindow.RestoreAndActivate();
    }

    /// <summary>
    /// Shows a balloon notification from the system tray.
    /// </summary>
    public void ShowBalloon(string title, string text, ToolTipIcon icon = ToolTipIcon.Info, int timeout = 3000)
    {
        if (_disposed) return;
        try
        {
            _trayIcon.ShowBalloonTip(timeout, title, text, icon);
        }
        catch { }
    }

    /// <summary>
    /// Shows a scan result notification.
    /// </summary>
    public void NotifyScanComplete(string scanType, int issuesFound)
    {
        var icon = issuesFound > 5 ? ToolTipIcon.Warning :
                   issuesFound > 0 ? ToolTipIcon.Info : ToolTipIcon.None;
        var issueLabel = issuesFound == 1 ? "issue" : "issues";
        var msg = issuesFound > 0
            ? $"{scanType} scan complete: {issuesFound} {issueLabel} found. Click to review."
            : $"{scanType} scan complete: No issues found. Your system is healthy!";
        ShowBalloon("LogicFlow Scan Results", msg, icon);
    }

    private void OnQuickCleanFromTray()
    {
        bool allowed = _mainWindow.Dispatcher.Invoke(() =>
        {
            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                _mainWindow.RestoreAndActivate();
                if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
                {
                    return false;
                }
            }
            return Gate.Require(OmniLicense.Capability.Core, _mainWindow);
        });
        if (!allowed) return;

        ShowBalloon("LogicFlow", "Executing 1-Click Maintenance in background...", ToolTipIcon.Info, 2000);
        Task.Run(() =>
        {
            try
            {
                var settings = SettingsManager.Load();
                var cleaner = new JunkCleanerEngine { ExcludedPaths = settings.ScanExclusions ?? new() };
                var maintenance = new OneClickMaintenance();
                var report = maintenance.Run(junkCleaner: cleaner);
                double reclaimedMB = report.JunkBytesCleaned / (1024.0 * 1024.0);
                var filesLabel = report.JunkFilesCleaned == 1 ? "file" : "files";
                var tweaksLabel = report.SafeTweaksApplied == 1 ? "tweak" : "tweaks";
                ShowBalloon(
                    "1-Click Clean Complete",
                    $"Reclaimed {reclaimedMB:F1} MB. {report.JunkFilesCleaned} junk {filesLabel} cleaned, {report.SafeTweaksApplied} {tweaksLabel} applied.",
                    ToolTipIcon.Info);

                _mainWindow.Dispatcher.InvokeAsync(() =>
                {
                    _mainWindow.RefreshTelemetryFromTrayClean(reclaimedMB);
                });
            }
            catch (Exception ex)
            {
                ShowBalloon("Maintenance Error", ex.Message, ToolTipIcon.Warning);
            }
        });
    }

    private async Task OnToggleTurboFromTray(ToolStripMenuItem turboItem)
    {
        try
        {
            bool wasActive = _mainWindow.IsTurboModeActive;
            bool balloonSentBeforeSuppression = false;

            bool newState = await _mainWindow.Dispatcher.InvokeAsync(async () =>
            {
                return await _mainWindow.ToggleTurboFromTrayAsync(beforeSuppressNotifications: result =>
                {
                    balloonSentBeforeSuppression = true;
                    ShowBalloon(
                        "LogicFlow Turbo / Boost",
                        $"Turbo / Boost Mode ENGAGED: {result.MemoryFreedFormatted} RAM freed, {result.ProcessesKilled} background app(s) terminated.",
                        ToolTipIcon.Info,
                        2500);
                });
            }).Task.Unwrap();

            turboItem.Checked = newState;
            turboItem.Text = newState ? "🚀 Turbo Mode: ACTIVE (Boost ON)" : "🚀 Toggle Turbo / Boost";
            SetTooltipSafe(newState ? "LogicFlow — Turbo Boost ACTIVE" : "LogicFlow — Windows Cleanup & Security");

            if (newState != wasActive && !balloonSentBeforeSuppression)
            {
                string balloonMsg = newState
                    ? "Turbo / Boost Mode ENGAGED. High-performance plan active, non-essential background apps terminated."
                    : "Turbo / Boost Mode DEACTIVATED. Previous power plan and notification state restored.";

                ShowBalloon("LogicFlow Turbo / Boost", balloonMsg, ToolTipIcon.Info, 2500);
            }
        }
        catch (Exception ex)
        {
            ShowBalloon("Turbo / Boost Error", ex.Message, ToolTipIcon.Warning, 2500);
        }
    }

    private void OnQuickScanFromTray()
    {
        RestoreWindow();
        ShowBalloon("LogicFlow", "Starting full system scan...", ToolTipIcon.Info, 2000);
        _mainWindow.Dispatcher.InvokeAsync(() => _mainWindow.TriggerFullScan());
    }

    private void OnScanFromTray(string scanType)
    {
        RestoreWindow();
        ShowBalloon("LogicFlow", $"Starting {scanType} scan...", ToolTipIcon.Info, 2000);
        _mainWindow.Dispatcher.InvokeAsync(() =>
        {
            switch (scanType.ToLowerInvariant())
            {
                case "security":
                    _mainWindow.TriggerSecurityScan();
                    break;
                case "performance":
                    _mainWindow.TriggerPerformanceScan();
                    break;
                case "registry":
                    _mainWindow.TriggerRegistryScan();
                    break;
                default:
                    _mainWindow.TriggerFullScan();
                    break;
            }
        });
    }

    public void ExitApplication()
    {
        _mainWindow.PrepareForExit();
        Dispose();
        _mainWindow.Close();
        System.Windows.Application.Current?.Shutdown();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        catch { }
    }
}

/// <summary>
/// Professional dark color table for LogicFlow context menus.
/// Prevents light/white hover washouts and matches the Glassmorphic Dark Obsidian theme.
/// </summary>
public sealed class DarkMenuColorTable : ProfessionalColorTable
{
    private static readonly System.Drawing.Color ObsidianDark = System.Drawing.Color.FromArgb(13, 17, 23);       // #0D1117
    private static readonly System.Drawing.Color SlateHover = System.Drawing.Color.FromArgb(30, 41, 59);          // #1E293B
    private static readonly System.Drawing.Color SlateActive = System.Drawing.Color.FromArgb(22, 27, 34);         // #161B22
    private static readonly System.Drawing.Color ElectricCyan = System.Drawing.Color.FromArgb(0, 229, 255);       // #00E5FF
    private static readonly System.Drawing.Color BorderSlate = System.Drawing.Color.FromArgb(51, 65, 85);        // #334155

    // Dropdown Background
    public override System.Drawing.Color ToolStripDropDownBackground => ObsidianDark;
    public override System.Drawing.Color MenuStripGradientBegin => ObsidianDark;
    public override System.Drawing.Color MenuStripGradientEnd => ObsidianDark;

    // Left Gutter / Image Margin (eliminate gray default)
    public override System.Drawing.Color ImageMarginGradientBegin => ObsidianDark;
    public override System.Drawing.Color ImageMarginGradientMiddle => ObsidianDark;
    public override System.Drawing.Color ImageMarginGradientEnd => ObsidianDark;
    public override System.Drawing.Color ImageMarginRevealedGradientBegin => ObsidianDark;
    public override System.Drawing.Color ImageMarginRevealedGradientMiddle => ObsidianDark;
    public override System.Drawing.Color ImageMarginRevealedGradientEnd => ObsidianDark;

    // Hover / Selection Background (#1E293B)
    public override System.Drawing.Color MenuItemSelected => SlateHover;
    public override System.Drawing.Color MenuItemSelectedGradientBegin => SlateHover;
    public override System.Drawing.Color MenuItemSelectedGradientEnd => SlateHover;

    // Hover / Selection Accent Border (#00E5FF)
    public override System.Drawing.Color MenuItemBorder => ElectricCyan;

    // Pressed / Active Background (#161B22)
    public override System.Drawing.Color MenuItemPressedGradientBegin => SlateActive;
    public override System.Drawing.Color MenuItemPressedGradientMiddle => SlateActive;
    public override System.Drawing.Color MenuItemPressedGradientEnd => SlateActive;

    // Menu Outer Border
    public override System.Drawing.Color MenuBorder => BorderSlate;
    public override System.Drawing.Color ToolStripBorder => BorderSlate;

    // Separators
    public override System.Drawing.Color SeparatorDark => BorderSlate;
    public override System.Drawing.Color SeparatorLight => System.Drawing.Color.Transparent;

    // Checkmark / Radio Box Background
    public override System.Drawing.Color CheckBackground => SlateActive;
    public override System.Drawing.Color CheckSelectedBackground => SlateHover;
    public override System.Drawing.Color ButtonSelectedHighlight => SlateHover;
    public override System.Drawing.Color ButtonSelectedBorder => ElectricCyan;
}

/// <summary>
/// Custom dark ToolStripProfessionalRenderer ensuring high contrast, crisp text,
/// dark slate hover backgrounds, and subtle electric cyan borders.
/// </summary>
public sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
{
    private static readonly System.Drawing.Color ObsidianDark = System.Drawing.Color.FromArgb(13, 17, 23);       // #0D1117
    private static readonly System.Drawing.Color SlateHover = System.Drawing.Color.FromArgb(30, 41, 59);          // #1E293B
    private static readonly System.Drawing.Color SlateActive = System.Drawing.Color.FromArgb(22, 27, 34);         // #161B22
    private static readonly System.Drawing.Color ElectricCyan = System.Drawing.Color.FromArgb(0, 229, 255);       // #00E5FF
    private static readonly System.Drawing.Color BorderSlate = System.Drawing.Color.FromArgb(51, 65, 85);        // #334155
    private static readonly System.Drawing.Color TextDefault = System.Drawing.Color.FromArgb(226, 232, 240);     // #E2E8F0
    private static readonly System.Drawing.Color TextDisabled = System.Drawing.Color.FromArgb(100, 116, 139);    // #64748B

    public DarkMenuRenderer() : base(new DarkMenuColorTable())
    {
        RoundedEdges = false;
    }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item is not ToolStripMenuItem item)
        {
            base.OnRenderMenuItemBackground(e);
            return;
        }

        var g = e.Graphics;
        var fullRect = new System.Drawing.Rectangle(0, 0, item.Width, item.Height);

        // Always fill base background with obsidian dark to prevent edge bleed
        using (var bgBrush = new SolidBrush(ObsidianDark))
        {
            g.FillRectangle(bgBrush, fullRect);
        }

        if (item.Selected && item.Enabled)
        {
            var bounds = new System.Drawing.Rectangle(2, 1, item.Width - 4, item.Height - 2);
            var hoverColor = item.Pressed ? SlateActive : SlateHover;
            using (var hoverBrush = new SolidBrush(hoverColor))
            {
                g.FillRectangle(hoverBrush, bounds);
            }

            // Subtle electric cyan border (#00E5FF)
            using var borderPen = new Pen(System.Drawing.Color.FromArgb(160, ElectricCyan), 1f);
            g.DrawRectangle(borderPen, bounds.X, bounds.Y, bounds.Width - 1, bounds.Height - 1);
        }
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        e.Graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        var color = TextDefault;
        if (e.Item is ToolStripLabel)
        {
            color = ElectricCyan; // #00E5FF for title/version header
        }
        else if (!e.Item.Enabled)
        {
            color = TextDisabled;
        }
        else if (e.Item.Selected)
        {
            color = System.Drawing.Color.White; // #FFFFFF crisp white on hover to ensure high contrast against #1E293B
        }

        System.Windows.Forms.TextRenderer.DrawText(
            e.Graphics,
            e.Text,
            e.TextFont,
            e.TextRectangle,
            color,
            e.TextFormat);
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        var g = e.Graphics;
        var y = e.Item.Height / 2;
        using var pen = new Pen(BorderSlate, 1f);
        g.DrawLine(pen, 8, y, e.Item.Width - 8, y);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        var g = e.Graphics;
        using var pen = new Pen(BorderSlate, 1f);
        var rect = new System.Drawing.Rectangle(0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1);
        g.DrawRectangle(pen, rect);
    }

    protected override void OnRenderImageMargin(ToolStripRenderEventArgs e)
    {
        // Suppress default Windows gray gutter
        var g = e.Graphics;
        using var brush = new SolidBrush(ObsidianDark);
        g.FillRectangle(brush, e.AffectedBounds);
    }

    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
    {
        e.ArrowColor = e.Item?.Selected == true ? System.Drawing.Color.White : ElectricCyan;
        base.OnRenderArrow(e);
    }

    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
    {
        var g = e.Graphics;
        var rect = new System.Drawing.Rectangle(e.ImageRectangle.X, e.ImageRectangle.Y, e.ImageRectangle.Width, e.ImageRectangle.Height);
        using var brush = new SolidBrush(SlateActive);
        g.FillRectangle(brush, rect);
        using var pen = new Pen(ElectricCyan, 1.5f);
        g.DrawRectangle(pen, rect.X, rect.Y, rect.Width - 1, rect.Height - 1);

        using var checkPen = new Pen(ElectricCyan, 2f);
        int midX = rect.X + rect.Width / 2;
        int midY = rect.Y + rect.Height / 2;
        g.DrawLines(checkPen, new[]
        {
            new System.Drawing.Point(rect.X + 3, midY),
            new System.Drawing.Point(midX - 1, rect.Bottom - 4),
            new System.Drawing.Point(rect.Right - 3, rect.Y + 4)
        });
    }
}

