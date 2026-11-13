// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow Dashboard — Gate
// Declarative edition gating for buttons: <Button local:Gate.Requires="Core" .../>
// A class-level Click handler runs before any instance handler, so a blocked click never reaches the
// feature code. Missing/unknown capabilities fail closed (TierPolicy treats them as Pro).
// ─────────────────────────────────────────────────────────────────────────────

using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using OmniLicense;

namespace LogicFlow.Dashboard;

public static class Gate
{
    private const string LockPrefix = "🔒 ";

    public static readonly DependencyProperty RequiresProperty = DependencyProperty.RegisterAttached(
        "Requires", typeof(Capability?), typeof(Gate), new PropertyMetadata(null, OnRequiresChanged));

    private static readonly DependencyProperty BaseToolTipProperty = DependencyProperty.RegisterAttached(
        "BaseToolTip", typeof(string), typeof(Gate), new PropertyMetadata(null));

    private static readonly List<WeakReference<FrameworkElement>> TrackedElements = new();
    private static bool _editionSubscribed;

    /// <summary>Optional hook for automated STA tests to observe upgrade prompts without blocking on a modal dialog.</summary>
    public static Action<Window?, Capability>? UpgradePromptInterceptForTesting { get; set; }

    /// <summary>Optional capability allowance override for isolated unit tests.</summary>
    public static Func<Capability, bool>? CapabilityAllowanceOverrideForTesting { get; set; }

    private static bool IsCapabilityAllowed(Capability capability) =>
        CapabilityAllowanceOverrideForTesting is { } overrideFn
            ? overrideFn(capability)
            : EditionService.Instance.Allows(capability);

    public static Capability? GetRequires(DependencyObject d) => (Capability?)d.GetValue(RequiresProperty);
    public static void SetRequires(DependencyObject d, Capability? value) => d.SetValue(RequiresProperty, value);

    private static bool _installed;

    /// <summary>Registers the global click and toggle preview interceptors (idempotent). Call once at startup.</summary>
    public static void Install()
    {
        if (_installed) return;
        _installed = true;
        EventManager.RegisterClassHandler(typeof(ToggleButton), UIElement.PreviewMouseLeftButtonDownEvent, new MouseButtonEventHandler(OnTogglePreviewMouseDown));
        EventManager.RegisterClassHandler(typeof(ToggleButton), UIElement.PreviewKeyDownEvent, new System.Windows.Input.KeyEventHandler(OnTogglePreviewKeyDown));
        EventManager.RegisterClassHandler(typeof(System.Windows.Controls.Primitives.ButtonBase), System.Windows.Controls.Primitives.ButtonBase.ClickEvent, new RoutedEventHandler(OnClick));
        EventManager.RegisterClassHandler(typeof(MenuItem), MenuItem.ClickEvent, new RoutedEventHandler(OnClick));
        EnsureEditionSubscription();
    }

    private static void EnsureEditionSubscription()
    {
        if (_editionSubscribed) return;
        _editionSubscribed = true;
        EditionService.Instance.Changed += RefreshAllVisualCues;
    }

    private static void OnRequiresChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        EnsureEditionSubscription();
        if (d is not FrameworkElement fe) return;

        lock (TrackedElements)
        {
            TrackedElements.RemoveAll(wr => !wr.TryGetTarget(out var target) || ReferenceEquals(target, fe));
            if (e.NewValue is Capability)
            {
                TrackedElements.Add(new WeakReference<FrameworkElement>(fe));
            }
        }

        fe.Loaded -= OnElementLoaded;
        if (e.NewValue is Capability)
        {
            fe.Loaded += OnElementLoaded;
        }

        UpdateElementCue(fe);
    }

    private static void OnElementLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
            UpdateElementCue(fe);
    }

    public static void RefreshAllVisualCues()
    {
        List<FrameworkElement> snapshot = new();
        lock (TrackedElements)
        {
            for (int i = TrackedElements.Count - 1; i >= 0; i--)
            {
                if (TrackedElements[i].TryGetTarget(out var fe))
                    snapshot.Add(fe);
                else
                    TrackedElements.RemoveAt(i);
            }
        }

        foreach (var fe in snapshot)
        {
            if (fe.Dispatcher.CheckAccess())
                UpdateElementCue(fe);
            else
                fe.Dispatcher.InvokeAsync(() => UpdateElementCue(fe));
        }
    }

    public static void UpdateElementCue(FrameworkElement fe)
    {
        var cap = GetRequires(fe);
        var baseTip = (string?)fe.GetValue(BaseToolTipProperty);
        if (baseTip is null && fe.ToolTip is string existingStr && !existingStr.Contains("🔒 Requires ", StringComparison.Ordinal))
        {
            baseTip = existingStr;
            fe.SetValue(BaseToolTipProperty, baseTip);
        }

        if (cap is not { } capability)
        {
            if (baseTip is not null)
                fe.ToolTip = string.IsNullOrEmpty(baseTip) ? null : baseTip;
            UpdateLabelLockPrefix(fe, locked: false);
            return;
        }

        bool allowed = IsCapabilityAllowed(capability);
        if (allowed)
        {
            if (fe.ToolTip is string currentTip && currentTip.Contains("🔒 Requires ", StringComparison.Ordinal))
            {
                fe.ToolTip = string.IsNullOrEmpty(baseTip) ? null : baseTip;
            }
            UpdateLabelLockPrefix(fe, locked: false);
        }
        else
        {
            var needed = TierPolicy.RequiredEdition(capability);
            string lockNotice = needed == Edition.Community
                ? "🔒 Requires Community ($0) or Pro — click to switch edition"
                : "🔒 Requires Pro (14-day trial available) — click for options";
            fe.ToolTip = string.IsNullOrWhiteSpace(baseTip) ? lockNotice : $"{baseTip}\n{lockNotice}";
            UpdateLabelLockPrefix(fe, locked: true);
        }
    }

    private static void UpdateLabelLockPrefix(FrameworkElement fe, bool locked)
    {
        // Only decorate standard push Buttons and MenuItems whose Content/Header is a plain string
        if (fe is System.Windows.Controls.Button btn && fe is not ToggleButton && btn.Content is string btnText)
        {
            bool hasPrefix = btnText.StartsWith(LockPrefix, StringComparison.Ordinal);
            if (locked && !hasPrefix)
                btn.Content = LockPrefix + btnText;
            else if (!locked && hasPrefix)
                btn.Content = btnText[LockPrefix.Length..];
        }
        else if (fe is MenuItem mi && mi.Header is string headerText)
        {
            bool hasPrefix = headerText.StartsWith(LockPrefix, StringComparison.Ordinal);
            if (locked && !hasPrefix)
                mi.Header = LockPrefix + headerText;
            else if (!locked && hasPrefix)
                mi.Header = headerText[LockPrefix.Length..];
        }
    }

    private static void OnTogglePreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (TryInterceptGatedToggle(sender))
            e.Handled = true;
    }

    private static void OnTogglePreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key is Key.Space or Key.Enter && TryInterceptGatedToggle(sender))
            e.Handled = true;
    }

    private static bool TryInterceptGatedToggle(object sender)
    {
        if (sender is not ToggleButton toggle || GetRequires(toggle) is not { } capability)
            return false;

        // Always allow unchecking/disabling an already-active toggle even in Free tier (never trap users)
        if (toggle.IsChecked == true)
            return false;

        if (IsCapabilityAllowed(capability))
            return false;

        ShowPrompt(Window.GetWindow(toggle), capability);
        return true;
    }

    private static void OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not DependencyObject d || GetRequires(d) is not { } capability) return;
        if (IsCapabilityAllowed(capability)) return;

        // If a ToggleButton reached OnClick while transitioning to unchecked (IsChecked == false), permit reverting
        if (sender is ToggleButton toggle)
        {
            if (toggle.IsChecked == false)
                return;
            toggle.IsChecked = false;
        }

        e.Handled = true;
        ShowPrompt(Window.GetWindow(d), capability);
    }

    private static void ShowPrompt(Window? owner, Capability capability)
    {
        if (UpgradePromptInterceptForTesting is { } intercept)
        {
            intercept(owner, capability);
            return;
        }
        Dialogs.ShowUpgradePrompt(owner, capability);
    }

    /// <summary>For code paths that are not buttons (tray menu, timers, view-models). Shows the prompt when blocked.</summary>
    public static bool Require(Capability capability, Window? owner = null)
    {
        if (IsCapabilityAllowed(capability)) return true;
        ShowPrompt(owner ?? Application.Current?.MainWindow, capability);
        return false;
    }
}
