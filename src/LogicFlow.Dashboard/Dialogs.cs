// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow Dashboard — Dialogs
// Small code-built modal dialogs (upgrade prompt, text viewer, About) that share the app theme.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using OmniLicense;
using Button = System.Windows.Controls.Button;
using Image = System.Windows.Controls.Image;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace LogicFlow.Dashboard;

public static class Dialogs
{
    public const string ShieldPack = "pack://application:,,,/LogicFlow;component/Assets/Brand/shield_{0}.png";

    public static BitmapImage Shield(int size = 128)
    {
        var img = new BitmapImage();
        img.BeginInit();
        img.UriSource = new Uri(string.Format(ShieldPack, size), UriKind.Absolute);
        img.CacheOption = BitmapCacheOption.OnLoad;
        img.EndInit();
        img.Freeze();
        return img;
    }

    public static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { Debug.WriteLine($"[Dialogs] Could not open {url}: {ex.Message}"); }
    }
    private static Brush Res(string key, Brush fallback)
        => Application.Current?.TryFindResource(key) as Brush ?? fallback;

    private static Window Create(Window? owner, string title, double width, double height)
    {
        var w = new Window
        {
            Title = title,
            Width = width,
            Height = height,
            SizeToContent = SizeToContent.Height,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = owner is { IsLoaded: true } ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen,
            Background = Res("BrandDarkBrush", new SolidColorBrush(Color.FromRgb(0x0A, 0x0E, 0x1A))),
            Foreground = Res("TextPrimaryBrush", Brushes.White),
            FontFamily = Application.Current?.TryFindResource("AppFont") as FontFamily ?? new FontFamily("Segoe UI"),
            ShowInTaskbar = false
        };
        w.SetResourceReference(Window.BackgroundProperty, "BrandDarkBrush");
        w.SetResourceReference(Window.ForegroundProperty, "TextPrimaryBrush");
        w.SourceInitialized += (_, _) => MainWindow.ApplyWindowTitleBarTheme(w);
        if (owner is { IsLoaded: true }) w.Owner = owner;
        try { w.Icon = Shield(64); } catch { /* icon is cosmetic */ }
        return w;
    }

    public static Func<Window, bool?>? WindowHostOverrideForTesting { get; set; }

    private static bool? ShowModalWindow(Window w)
        => WindowHostOverrideForTesting != null ? WindowHostOverrideForTesting(w) : w.ShowDialog();

    public static void ApplyWindowUiScale(Window w)
    {
        try
        {
            double scale = Math.Clamp(SettingsManager.Load().UiScale, 1.0, 1.5);
            if (Math.Abs(scale - 1.0) <= 0.01) return;

            if (w.Content is FrameworkElement fe)
            {
                fe.LayoutTransform = new ScaleTransform(scale, scale);
            }

            var workArea = SystemParameters.WorkArea;
            double maxW = workArea.Width > 0 ? Math.Max(480, workArea.Width - 32) : 1440;
            double maxH = workArea.Height > 0 ? Math.Max(360, workArea.Height - 32) : 900;

            if (!double.IsNaN(w.Width) && w.Width > 0)
            {
                w.Width = Math.Min(Math.Round(w.Width * scale), maxW);
            }
            if (double.IsFinite(w.MaxHeight) && w.MaxHeight > 0)
            {
                double scaledMaxH = Math.Round(w.MaxHeight * scale);
                w.MaxHeight = workArea.Height > 0 ? Math.Min(scaledMaxH, maxH) : scaledMaxH;
            }
            if (w.SizeToContent == SizeToContent.Manual && !double.IsNaN(w.Height) && w.Height > 0)
            {
                w.Height = Math.Min(Math.Round(w.Height * scale), maxH);
            }
        }
        catch { }
    }

    private static void AttachContent(Window w, FrameworkElement content)
    {
        w.Content = content;
        ApplyWindowUiScale(w);
    }

    private static Button MakeButton(string text, bool primary, RoutedEventHandler onClick, bool isCancel = false, bool isDefault = false, bool destructive = false)
    {
        var b = new Button
        {
            Content = text,
            Height = 34,
            MinWidth = 96,
            Padding = new Thickness(14, 0, 14, 0),
            Margin = new Thickness(8, 4, 0, 0),
            IsCancel = isCancel,
            IsDefault = isDefault
        };
        string styleKey = destructive ? "DangerButtonStyle" : (primary ? "ActionButton" : "OutlineButton");
        if (Application.Current?.TryFindResource(styleKey) is Style s) b.Style = s;
        b.Click += onClick;
        return b;
    }

    private static TextBlock Body(string text, double size = 13, Brush? brush = null) => new()
    {
        Text = text,
        FontSize = size,
        TextWrapping = TextWrapping.Wrap,
        Foreground = brush ?? Res("TextSecondaryBrush", Brushes.LightGray),
        Margin = new Thickness(0, 0, 0, 10)
    };

    // ─── Themed Info / Warning / Confirm Dialogs ────────────────────────

    public static void ShowMessage(Window? owner, string title, string message, bool isWarningOrError = false)
    {
        owner ??= Application.Current?.MainWindow;
        var w = Create(owner, title, 480, 240);
        var root = new StackPanel { Margin = new Thickness(24) };

        var header = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 0, 12) };
        var iconBlock = new TextBlock
        {
            Text = isWarningOrError ? "⚠️" : "ℹ️",
            FontSize = 20,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 10, 0)
        };
        DockPanel.SetDock(iconBlock, Dock.Left);
        header.Children.Add(iconBlock);
        header.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 16,
            FontWeight = FontWeights.Bold,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = isWarningOrError
                ? Res("WarningAmberBrush", Brushes.Orange)
                : Res("TextPrimaryBrush", Brushes.White)
        });
        root.Children.Add(header);
        root.Children.Add(Body(message, 13));

        var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0) };
        var okBtn = MakeButton("OK", primary: true, (_, _) => w.Close(), isCancel: true, isDefault: true);
        buttons.Children.Add(okBtn);
        root.Children.Add(buttons);

        AttachContent(w, root);
        w.Loaded += (_, _) => okBtn.Focus();
        ShowModalWindow(w);
    }

    public static bool Confirm(
        Window? owner,
        string title,
        string message,
        string confirmText = "Continue",
        string cancelText = "Cancel",
        bool defaultCancel = false,
        bool destructive = false)
    {
        owner ??= Application.Current?.MainWindow;
        bool confirmed = false;
        var w = Create(owner, title, 500, 260);
        var root = new StackPanel { Margin = new Thickness(24) };

        var header = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 0, 12) };
        var shieldImg = new Image { Source = Shield(64), Width = 32, Height = 32, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
        DockPanel.SetDock(shieldImg, Dock.Left);
        header.Children.Add(shieldImg);
        header.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 16,
            FontWeight = FontWeights.Bold,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = destructive
                ? Res("DangerRedBrush", Brushes.IndianRed)
                : Res("TextPrimaryBrush", Brushes.White)
        });
        root.Children.Add(header);
        root.Children.Add(Body(message, 13));

        var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var cancelBtn = MakeButton(cancelText, primary: false, (_, _) => { confirmed = false; w.Close(); }, isCancel: true, isDefault: defaultCancel);
        var confirmBtn = MakeButton(confirmText, primary: !destructive, (_, _) => { confirmed = true; w.Close(); }, isCancel: false, isDefault: !defaultCancel, destructive: destructive);
        buttons.Children.Add(cancelBtn);
        buttons.Children.Add(confirmBtn);
        root.Children.Add(buttons);

        AttachContent(w, root);
        w.Loaded += (_, _) => (defaultCancel ? cancelBtn : confirmBtn).Focus();
        ShowModalWindow(w);
        return confirmed;
    }

    // ─── Upgrade prompt ─────────────────────────────────────────────────

    /// <summary>Explains why a capability is locked and offers the right next step. Never blocks the app.</summary>
    public static void ShowUpgradePrompt(Window? owner, Capability capability)
    {
        var edition = EditionService.Instance.Current;
        var needed = TierPolicy.RequiredEdition(capability);
        var w = Create(owner, "LogicFlow — " + TierPolicy.CapabilityName(capability), 520, 270);

        var root = new StackPanel { Margin = new Thickness(24) };
        var header = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 0, 14) };
        var shieldImg = new Image { Source = Shield(64), Width = 40, Height = 40, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
        DockPanel.SetDock(shieldImg, Dock.Left);
        header.Children.Add(shieldImg);
        header.Children.Add(new TextBlock
        {
            Text = needed == Edition.Pro ? "Pro Feature (14-Day Trial Available)" : "Available Free in Community ($0)",
            FontSize = 17, FontWeight = FontWeights.Bold, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center,
            Foreground = Res("TextPrimaryBrush", Brushes.White)
        });
        root.Children.Add(header);
        root.Children.Add(Body(TierPolicy.UpgradeMessage(edition, capability)));

        var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0) };
        buttons.Children.Add(MakeButton("Not Now", primary: false, (_, _) => w.Close(), isCancel: true));

        if (edition == Edition.Free && needed == Edition.Community)
        {
            buttons.Children.Add(MakeButton("See Plans", primary: false, (_, _) => { OpenUrl(PriceSheet.PricingUrl); w.Close(); }));
            var switchBtn = MakeButton("Switch to Community ($0)", primary: true, (_, _) =>
            {
                w.Close();
                ConsentWindow.ShowFromSettings(owner);
            }, isDefault: true);
            buttons.Children.Add(switchBtn);
            w.Loaded += (_, _) => switchBtn.Focus();
        }
        else if (needed == Edition.Pro && EditionService.Instance.ActiveTrial is null)
        {
            buttons.Children.Add(MakeButton("See Plans", primary: false, (_, _) => { OpenUrl(PriceSheet.PricingUrl); w.Close(); }));
            var trialBtn = MakeButton("Start 14-Day Pro Trial", primary: true, (_, _) =>
            {
                EditionService.Instance.StartProTrial();
                App.OnConsentChanged();
                w.Close();
            }, isDefault: true);
            buttons.Children.Add(trialBtn);
            w.Loaded += (_, _) => trialBtn.Focus();
        }
        else
        {
            var plansBtn = MakeButton("See Plans", primary: true, (_, _) => { OpenUrl(PriceSheet.PricingUrl); w.Close(); }, isDefault: true);
            buttons.Children.Add(plansBtn);
            w.Loaded += (_, _) => plansBtn.Focus();
        }

        root.Children.Add(buttons);
        AttachContent(w, root);
        ShowModalWindow(w);
    }

    // ─── Offline Legal & Help Viewers ───────────────────────────────────

    public static (string Title, string FileName, string Url) MapLegalSlug(string slugOrFile)
    {
        var safeSlug = (slugOrFile ?? "eula").Trim();
        var key = safeSlug.ToLowerInvariant();
        if (key.EndsWith(".md", StringComparison.Ordinal))
            key = key[..^3];

        return key switch
        {
            "eula" => ("End User License Agreement (EULA)", "eula.md", PriceSheet.EulaUrl),
            "privacy" or "privacy-policy" => ("Privacy Policy", "privacy.md", PriceSheet.PrivacyUrl),
            "terms" or "tos" => ("Terms of Service", "terms.md", PriceSheet.TermsUrl),
            "refund" or "refunds" => ("Refund Policy", "refund.md", PriceSheet.RefundUrl),
            "third-party" or "third-party-notices" => ("Third-Party Software Notices", "third-party-notices.md", PriceSheet.ThirdPartyUrl),
            "security" or "security-policy" => ("Security & Architecture Policy", "security-policy.md", PriceSheet.SecurityUrl),
            _ => ($"LogicFlow — {safeSlug}", safeSlug.EndsWith(".md", StringComparison.OrdinalIgnoreCase) ? safeSlug : $"{safeSlug}.md", PriceSheet.EulaUrl)
        };
    }

    public static string? ResolveBundledLegalText(string docFileName)
    {
        var (_, resolvedFile, _) = MapLegalSlug(docFileName);
        if (string.Equals(resolvedFile, "eula.md", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(docFileName, "EULA.txt", StringComparison.OrdinalIgnoreCase))
        {
            var embedded = EditionService.EulaText();
            if (!string.IsNullOrWhiteSpace(embedded))
                return embedded;
        }

        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var candidates = new[]
        {
            System.IO.Path.Combine(baseDir, "Docs", "legal", resolvedFile),
            System.IO.Path.Combine(baseDir, "..", "..", "..", "..", "..", "Docs", "legal", resolvedFile),
            System.IO.Path.Combine(baseDir, "..", "..", "..", "..", "Docs", "legal", resolvedFile),
            System.IO.Path.Combine(baseDir, "..", "..", "..", "Docs", "legal", resolvedFile)
        };

        foreach (var candidate in candidates)
        {
            try
            {
                if (System.IO.File.Exists(candidate))
                    return System.IO.File.ReadAllText(candidate);
            }
            catch { }
        }

        return null;
    }

    public static void ShowLegalDoc(Window? owner, string slug)
    {
        var (title, docFile, url) = MapLegalSlug(slug);
        ShowLegalDoc(owner, title, docFile, url);
    }

    public static void ShowLegalDoc(Window? owner, string title, string docFileName, string onlineUrl)
    {
        var text = ResolveBundledLegalText(docFileName);
        ShowText(
            owner,
            title,
            text ?? $"This document is available online at:\n{onlineUrl}",
            "Open Online",
            onlineUrl);
    }

    public static void ShowHelpDialog(Window? owner)
    {
        const string helpText = """
            LOGICFLOW v1.0 — OFFLINE REFERENCE & SHORTCUTS
            ==============================================

            KEYBOARD & NAVIGATION
            • F1                      Open this offline reference guide
            • Esc                     Dismiss modal dialogs and prompts
            • Tab / Shift+Tab         Move keyboard focus across controls and list items
            • Enter / Space           Activate the focused button, toggle, or row

            COMMAND-LINE & HEADLESS BOOST (/boost)
            • LogicFlow.exe /boost        Engage Gaming Turbo Boost headlessly in the system tray
                                          (never steals focus from full-screen games or opens a window)
            • LogicFlow.exe /boost off    Disengage Turbo Boost and restore prior power/toast settings
            • LogicFlow.exe --tray        Start LogicFlow minimized in the system tray
            • LogicFlow.exe --auto-maintenance
                                          Run scheduled 1-Click Maintenance headlessly and exit
            • lf.exe boost [gaming|work|battery|status|off]
                                          CLI boost control & persisted status inspection

            SAFETY, REVERSIBILITY & UNPACKING
            • Every revert/unpack operation (HyperStore unpack, GameVault NTFS WOF restore,
              Windows Tweak revert, AI Privacy revert, Defender revert, Registry backups)
              is ALWAYS unlocked on every tier — even Free ($0, zero-telemetry) or after a
              Pro trial expires. Your data and settings are never held hostage.

            LOCAL AI & PRIVACY
            • Pulse Deterministic Engine runs 100% locally in C# with zero network calls.
            • Gemma 4 Local Sidecar runs offline on localhost via llama-server (verified SHA-256).
            • Cloud AI fallback is disabled by default unless explicitly enabled in Settings.
            • Free ($0) writes zero device identity files and transmits zero telemetry.

            DATA & LOG LOCATIONS
            • User Settings & Consent:    %LOCALAPPDATA%\LogicFlow
            • Backups & Undo Snapshots:   %APPDATA%\LogicFlow
            • Shared License Store:       %APPDATA%\DelgadoLogic\Shared (licensed tiers only)
            • Service Audit Logs:         %PROGRAMDATA%\LogicFlow\Logs
            • Service Health Reports:     %PROGRAMDATA%\LogicFlow\Reports
            """;

        ShowText(owner, "LogicFlow Help & Keyboard Reference (F1)", helpText, "Online Documentation", "https://delgadologic.tech/support");
    }

    // ─── Text viewer (EULA, "View what is sent") ────────────────────────

    public static void ShowText(Window? owner, string title, string text, string? linkText = null, string? linkUrl = null)
    {
        var w = Create(owner, title, 720, 640);
        w.SizeToContent = SizeToContent.Manual;
        w.ResizeMode = ResizeMode.CanResizeWithGrip;
        w.MinWidth = 520;
        w.MinHeight = 360;

        var grid = new Grid { Margin = new Thickness(20) };
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var box = new TextBox
        {
            Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas"), FontSize = 12,
            Background = Res("BrandDarkPanelBrush", new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A))),
            Foreground = Res("TextPrimaryBrush", Brushes.White),
            BorderThickness = new Thickness(1),
            BorderBrush = Res("BorderSubtleBrush", new SolidColorBrush(Color.FromRgb(0x1E, 0x29, 0x3B))),
            Padding = new Thickness(12, 10, 12, 14)
        };
        box.SetResourceReference(TextBox.BackgroundProperty, "BrandDarkPanelBrush");
        box.SetResourceReference(TextBox.ForegroundProperty, "TextPrimaryBrush");
        box.SetResourceReference(TextBox.BorderBrushProperty, "BorderSubtleBrush");
        Grid.SetRow(box, 0);
        grid.Children.Add(box);

        var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        if (linkText is not null && linkUrl is not null)
            buttons.Children.Add(MakeButton(linkText, false, (_, _) => OpenUrl(linkUrl)));
        var closeBtn = MakeButton("Close", true, (_, _) => w.Close(), isCancel: true, isDefault: true);
        buttons.Children.Add(closeBtn);
        Grid.SetRow(buttons, 1);
        grid.Children.Add(buttons);

        AttachContent(w, grid);
        w.Loaded += (_, _) => closeBtn.Focus();
        ShowModalWindow(w);
    }

    // ─── About ──────────────────────────────────────────────────────────

    public static void ShowAbout(Window? owner)
    {
        var version = typeof(Dialogs).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        var w = Create(owner, "About LogicFlow", 548, 440);

        var root = new StackPanel { Margin = new Thickness(24, 28, 24, 28) };
        root.Children.Add(new Image { Source = Shield(128), Width = 96, Height = 96, Margin = new Thickness(0, 0, 0, 12) });
        root.Children.Add(new TextBlock { Text = "LogicFlow", FontSize = 24, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, Foreground = Res("TextPrimaryBrush", Brushes.White) });
        root.Children.Add(new TextBlock { Text = $"Version {version} · {EditionService.Instance.Current.DisplayName()} Edition", FontSize = 13, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center, Foreground = Res("TextSecondaryBrush", Brushes.LightGray), Margin = new Thickness(0, 2, 0, 14) });
        var descBody = Body("Windows system cleanup, security checks, driver, and storage tools.\nWindows 10 (1607+) and Windows 11, 64-bit.", 13);
        descBody.TextAlignment = TextAlignment.Center;
        descBody.HorizontalAlignment = HorizontalAlignment.Center;
        root.Children.Add(descBody);
        var copyBody = Body($"© {DateTime.UtcNow.Year} {PriceSheet.LegalEntity}\nSupport: {PriceSheet.SupportEmail}", 12);
        copyBody.TextAlignment = TextAlignment.Center;
        copyBody.HorizontalAlignment = HorizontalAlignment.Center;
        root.Children.Add(copyBody);

        var links = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 6, 0, 14) };
        void AddDocLink(string text, string docFile, string url)
        {
            var b = new Button { Content = text, FontSize = 12, Margin = new Thickness(3), Padding = new Thickness(9, 4, 9, 4), Cursor = System.Windows.Input.Cursors.Hand };
            if (Application.Current?.TryFindResource("OutlineButton") is Style s) b.Style = s;
            b.Click += (_, _) => ShowLegalDoc(w, $"LogicFlow — {text}", docFile, url);
            links.Children.Add(b);
        }
        AddDocLink("EULA", "eula.md", PriceSheet.EulaUrl);
        AddDocLink("Terms", "terms.md", PriceSheet.TermsUrl);
        AddDocLink("Privacy", "privacy.md", PriceSheet.PrivacyUrl);
        AddDocLink("Refunds", "refund.md", PriceSheet.RefundUrl);
        AddDocLink("Third-Party Notices", "third-party-notices.md", PriceSheet.ThirdPartyUrl);
        AddDocLink("Security", "security-policy.md", PriceSheet.SecurityUrl);
        root.Children.Add(links);

        var close = MakeButton("Close", true, (_, _) => w.Close(), isCancel: true, isDefault: true);
        close.HorizontalAlignment = HorizontalAlignment.Center;
        root.Children.Add(close);

        AttachContent(w, root);
        w.Loaded += (_, _) => close.Focus();
        ShowModalWindow(w);
    }
}
