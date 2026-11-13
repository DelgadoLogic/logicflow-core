using System.Windows;
using System.Windows.Controls;
using OmniLicense;
using OmniPulse;

namespace LogicFlow.Dashboard;

/// <summary>
/// 3-Step First-Run Setup Wizard (and 2-Step Settings Edition/Region dialog):
/// Step 1: Country/Region selection &amp; EULA acceptance
/// Step 2: Edition choice &amp; region-adapted diagnostics sharing
/// Step 3: Startup &amp; application preferences (Recommended vs. Custom preset)
/// </summary>
public partial class ConsentWindow : Window
{
    private readonly ConsentStore _store;
    private readonly bool _isFirstRunMode;
    private bool _updating;
    private int _currentStep = 1;
    private PrivacyRegion _lastAppliedRegion;
    private EditionChoice _lastEdition = EditionChoice.Community;

    public ConsentWindow() : this(EditionService.Instance.Consent, isFirstRunMode: true)
    {
    }

    public ConsentWindow(ConsentStore store, bool isFirstRunMode = true)
    {
        _store = store ?? EditionService.Instance.Consent;
        _isFirstRunMode = isFirstRunMode;

        InitializeComponent();
        Dialogs.ApplyWindowUiScale(this);
        ClampToWorkArea();
        SourceInitialized += (_, _) =>
        {
            MainWindow.ApplyWindowTitleBarTheme(this);
            ClampToWorkArea();
        };
        DpiChanged += (_, _) => ClampToWorkArea();

        var current = _store.Current;
        var detectedIso = _store.DetectWindowsIsoCode();
        var region = current.RegionConfirmed ? current.Region : PrivacyRegionExtensions.FromCountryCode(detectedIso);

        _updating = true;
        try
        {
            SelectRegionItem(region);
            RegionDetectionNote.Text = $"Auto-detected from your Windows region setting ({detectedIso}) — no IP address lookup is performed.";

            ChkEula.IsChecked = current.EulaAcceptedAt is not null || _store.IsInstallerEulaAccepted();

            ProTitle.Text = $"Pro — {PriceSheet.Format(PriceSheet.ProLaunchPrice)} launch ({PriceSheet.Format(PriceSheet.ProPrice)} regular) · 14-day Pro trial included";
            ProText.Text = $"{PriceSheet.ProDevices} devices, commercial use, background automation, advanced recovery, priority support. " +
                           $"{PriceSheet.UpdatesPolicy}. {PriceSheet.RefundDays}-day refund. Diagnostics sharing is optional and off by default. " +
                           "Selecting Pro starts your 14-day Pro trial immediately (or you can enter a license key in Settings).";
            Footer.Text = $"{PriceSheet.LegalEntity} · {PriceSheet.SupportEmail}";

            if (_store.HasDecided)
            {
                (current.Edition switch
                {
                    EditionChoice.Free => RbFree,
                    EditionChoice.Pro => RbPro,
                    _ => RbCommunity
                }).IsChecked = true;
                _lastEdition = current.Edition;
                ChkStandard.IsChecked = current.Level >= ConsentLevel.Standard;
                ChkExtended.IsChecked = current.Level >= ConsentLevel.Extended;
            }
            else
            {
                RbCommunity.IsChecked = true;
                _lastEdition = EditionChoice.Community;
                ChkStandard.IsChecked = true;
                ChkExtended.IsChecked = !region.IsStrict();
            }

            _lastAppliedRegion = region;
            LoadInitialPreferences();
        }
        finally
        {
            _updating = false;
        }

        ApplyRegionDefaults(preserveStoredIfSameRegion: true);
        UpdateUi();
    }

    public int CurrentStep => _currentStep;

    public EditionChoice SelectedEdition =>
        RbFree.IsChecked == true ? EditionChoice.Free : RbPro.IsChecked == true ? EditionChoice.Pro : EditionChoice.Community;

    public PrivacyRegion SelectedRegion =>
        Enum.TryParse<PrivacyRegion>((CmbRegion.SelectedItem as ComboBoxItem)?.Tag as string, out var r) ? r : PrivacyRegion.RestOfWorld;

    public bool IsRecommendedPresetActive =>
        ChkPrefStartWithWindows.IsChecked != true &&
        ChkPrefMinimizeToTray.IsChecked == true &&
        ChkPrefCheckUpdates.IsChecked == true &&
        ChkPrefScanSmart.IsChecked == true &&
        ChkPrefTelemetryBlocking.IsChecked != true;

    public void SelectRegionItem(PrivacyRegion region)
    {
        foreach (ComboBoxItem item in CmbRegion.Items)
        {
            if (item.Tag as string == region.ToString())
            {
                CmbRegion.SelectedItem = item;
                return;
            }
        }
    }

    private void LoadInitialPreferences()
    {
        if (!_store.HasDecided)
        {
            ApplyRecommendedPreferences();
            return;
        }

        try
        {
            var settings = SettingsManager.Load();
            if (settings.FirstRunDate == DateTimeOffset.MinValue)
            {
                ApplyRecommendedPreferences();
            }
            else
            {
                ChkPrefStartWithWindows.IsChecked = settings.StartWithWindows;
                ChkPrefMinimizeToTray.IsChecked = settings.MinimizeToTray;
                ChkPrefCheckUpdates.IsChecked = settings.CheckForUpdatesAutomatically;
                ChkPrefScanSmart.IsChecked = settings.ScanSmartOnStartup;
                ChkPrefTelemetryBlocking.IsChecked = settings.EnableTelemetryBlocking;
            }
        }
        catch
        {
            ApplyRecommendedPreferences();
        }
    }

    public void ApplyRecommendedPreferences()
    {
        bool prev = _updating;
        _updating = true;
        try
        {
            ChkPrefStartWithWindows.IsChecked = false;
            ChkPrefMinimizeToTray.IsChecked = true;
            ChkPrefCheckUpdates.IsChecked = true;
            ChkPrefScanSmart.IsChecked = true;
            ChkPrefTelemetryBlocking.IsChecked = false;
        }
        finally
        {
            _updating = prev;
        }
        UpdateUi();
    }

    /// <summary>
    /// Applies region-appropriate default state to Extended diagnostics on Step 2:
    /// Strict regions (EU/EEA, UK, CH, CA, BR, JP, KR, IN) initialize ChkExtended = false (opt-in).
    /// Non-strict regions (US, MX, AU/NZ, RestOfWorld) initialize ChkExtended = true (pre-checked, toggleable).
    /// </summary>
    public void ApplyRegionDefaults(bool preserveStoredIfSameRegion = false)
    {
        var region = SelectedRegion;
        var strict = region.IsStrict();
        var current = _store.Current;

        bool prev = _updating;
        _updating = true;
        try
        {
            if (SelectedEdition == EditionChoice.Community)
            {
                ChkStandard.IsChecked = true;
                ChkStandard.IsEnabled = false;
                ChkExtended.IsEnabled = true;

                if (preserveStoredIfSameRegion && _store.HasDecided && current.RegionConfirmed &&
                    current.Region == region && current.Edition == EditionChoice.Community)
                {
                    ChkExtended.IsChecked = current.Level >= ConsentLevel.Extended;
                }
                else
                {
                    ChkExtended.IsChecked = !strict;
                }

                _lastAppliedRegion = region;
            }
        }
        finally
        {
            _updating = prev;
        }
    }

    public void GoToStep(int step)
    {
        int maxStep = _isFirstRunMode ? 3 : 2;
        if (step < 1) step = 1;
        if (step > maxStep) step = maxStep;

        if (step == 2 && _lastAppliedRegion != SelectedRegion)
        {
            ApplyRegionDefaults(preserveStoredIfSameRegion: false);
        }

        _currentStep = step;
        UpdateUi();
    }

    private void UpdateUi()
    {
        if (_updating || !IsInitialized) return;
        _updating = true;
        try
        {
            var edition = SelectedEdition;
            var region = SelectedRegion;
            var strict = region.IsStrict();
            int totalSteps = _isFirstRunMode ? 3 : 2;

            // Step indicator & panel visibility
            Step1RegionPanel.Visibility = _currentStep == 1 ? Visibility.Visible : Visibility.Collapsed;
            Step2EditionPanel.Visibility = _currentStep == 2 ? Visibility.Visible : Visibility.Collapsed;
            Step3PreferencesPanel.Visibility = _currentStep == 3 ? Visibility.Visible : Visibility.Collapsed;

            StepIndicatorText.Text = _currentStep switch
            {
                1 => $"Step 1 of {totalSteps} · Region & License Agreement",
                2 => $"Step 2 of {totalSteps} · Edition & Diagnostics",
                _ => $"Step 3 of {totalSteps} · Startup & App Preferences"
            };
            StepRegionBadge.Text = _currentStep >= 2 ? $"Region: {region.DisplayName()}" : "";

            // Edition & Diagnostics state on Step 2
            TelemetryPanel.Visibility = edition == EditionChoice.Free ? Visibility.Collapsed : Visibility.Visible;

            if (edition == EditionChoice.Community)
            {
                TelemetryIntro.Text = "Community is provided at $0 (no monetary cost) in exchange for pseudonymous diagnostics sharing. Standard diagnostics sharing is required while using Community.";
                ChkStandard.IsChecked = true;
                ChkStandard.IsEnabled = false;
                ChkExtended.IsEnabled = true;
                ExtendedNote.Text = strict
                    ? "Optional in your region (unchecked by default). Community works with Standard diagnostics alone."
                    : "Pre-selected by default in your region. You can uncheck this if you prefer Standard diagnostics only.";
            }
            else if (edition == EditionChoice.Pro)
            {
                TelemetryIntro.Text = "Optional for Pro. Leave both unchecked to share nothing.";
                ChkStandard.IsEnabled = true;
                ChkExtended.IsEnabled = ChkStandard.IsChecked == true;
                if (ChkStandard.IsChecked != true) ChkExtended.IsChecked = false;
                ExtendedNote.Text = "Optional.";
            }

            // Step 3 preset indicator
            if (PresetStatusText != null)
            {
                PresetStatusText.Text = IsRecommendedPresetActive
                    ? "Preset: Recommended Settings"
                    : "Preset: Custom Settings";
            }

            // Bottom navigation buttons
            bool eulaOk = ChkEula.IsChecked == true;
            BtnBack.Visibility = _currentStep > 1 ? Visibility.Visible : Visibility.Collapsed;
            BtnDecline.Visibility = (_currentStep == 2 && edition == EditionChoice.Community) ? Visibility.Visible : Visibility.Collapsed;
            BtnDecline.IsEnabled = eulaOk;
            BtnContinue.IsEnabled = eulaOk;

            BtnContinue.Content = _currentStep switch
            {
                1 => "Next: Choose Edition →",
                2 => _isFirstRunMode ? "Next: App Preferences →" : "Save & Continue",
                _ => "Finish & Launch LogicFlow"
            };
        }
        finally
        {
            _updating = false;
        }
    }

    private void OnEditionChanged(object sender, RoutedEventArgs e)
    {
        if (_updating || !IsInitialized) return;
        var newEdition = SelectedEdition;
        if (newEdition != _lastEdition)
        {
            if (newEdition == EditionChoice.Pro)
            {
                _updating = true;
                try
                {
                    if (_store.HasDecided && _store.Current.Edition == EditionChoice.Pro)
                    {
                        ChkStandard.IsChecked = _store.Current.Level >= ConsentLevel.Standard;
                        ChkExtended.IsChecked = _store.Current.Level >= ConsentLevel.Extended;
                    }
                    else
                    {
                        ChkStandard.IsChecked = false;
                        ChkExtended.IsChecked = false;
                    }
                }
                finally { _updating = false; }
            }
            else if (newEdition == EditionChoice.Community)
            {
                ApplyRegionDefaults(preserveStoredIfSameRegion: true);
            }
            _lastEdition = newEdition;
        }
        UpdateUi();
    }

    private void OnRegionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updating || !IsInitialized) return;
        ApplyRegionDefaults(preserveStoredIfSameRegion: false);
        UpdateUi();
    }

    private void OnTelemetryBoxChanged(object sender, RoutedEventArgs e) => UpdateUi();

    private void OnPreferenceBoxChanged(object sender, RoutedEventArgs e) => UpdateUi();

    private void OnRecommendedPresetClick(object sender, RoutedEventArgs e) => ApplyRecommendedPreferences();

    private void OnReadEula(object sender, RoutedEventArgs e)
        => Dialogs.ShowLegalDoc(this, "End User License Agreement", "eula.md", PriceSheet.EulaUrl);

    private void OnOpenPrivacy(object sender, RoutedEventArgs e)
        => Dialogs.ShowLegalDoc(this, "Privacy Policy", "privacy.md", PriceSheet.PrivacyUrl);

    private void OnOpenTerms(object sender, RoutedEventArgs e)
        => Dialogs.ShowLegalDoc(this, "Terms of Service", "terms.md", PriceSheet.TermsUrl);

    private void OnBack(object sender, RoutedEventArgs e)
    {
        if (_currentStep > 1)
            GoToStep(_currentStep - 1);
    }

    private void OnUseFree(object sender, RoutedEventArgs e)
    {
        RbFree.IsChecked = true;
        if (_isFirstRunMode && _currentStep == 2)
        {
            GoToStep(3);
            return;
        }
        _store.SetRegion(SelectedRegion);
        _store.SwitchToFree(EditionService.EulaVersion, EditionService.EulaSha256());
        DelgadoLogic.Core.DelgadoLogicIdentity.PurgePersistedIdentity();
        Finish();
    }

    private void OnContinue(object sender, RoutedEventArgs e)
    {
        if (_currentStep == 1)
        {
            GoToStep(2);
            return;
        }

        if (_currentStep == 2 && _isFirstRunMode)
        {
            GoToStep(3);
            return;
        }

        CommitDecisionAndFinish();
    }

    public void CommitDecisionAndFinish()
    {
        var edition = SelectedEdition;
        var region = SelectedRegion;
        var eulaVersion = EditionService.EulaVersion;
        var eulaHash = EditionService.EulaSha256();

        if (edition == EditionChoice.Free)
        {
            _store.SwitchToFree(eulaVersion, eulaHash);
            DelgadoLogic.Core.DelgadoLogicIdentity.PurgePersistedIdentity();
        }
        else
        {
            _store.Apply(edition, region, ChkStandard.IsChecked == true, ChkExtended.IsChecked == true, eulaVersion, eulaHash);
            if (edition == EditionChoice.Pro && ReferenceEquals(_store, EditionService.Instance.Consent))
            {
                EditionService.Instance.Refresh();
                if (EditionService.Instance.Current != Edition.Pro)
                {
                    EditionService.Instance.StartProTrial();
                }
            }
        }

        _store.SetRegion(region);

        if (_isFirstRunMode)
        {
            try
            {
                var settings = SettingsManager.Load();
                settings.StartWithWindows = ChkPrefStartWithWindows.IsChecked == true;
                settings.MinimizeToTray = ChkPrefMinimizeToTray.IsChecked == true;
                settings.CheckForUpdatesAutomatically = ChkPrefCheckUpdates.IsChecked == true;
                settings.ScanSmartOnStartup = ChkPrefScanSmart.IsChecked == true;
                settings.EnableTelemetryBlocking = ChkPrefTelemetryBlocking.IsChecked == true;
                SettingsManager.Save();
                SettingsManager.SetStartWithWindows(settings.StartWithWindows);
            }
            catch { }
        }

        Finish();
    }

    private void ClampToWorkArea()
    {
        try
        {
            double scale = 1.0;
            try { scale = Math.Clamp(SettingsManager.Load().UiScale, 1.0, 1.5); } catch { }
            var workArea = SystemParameters.WorkArea;
            double targetMaxH = Math.Round(840 * scale);
            if (workArea.Height > 0)
            {
                double availH = Math.Max(360, workArea.Height - 24);
                if (MinHeight > availH) MinHeight = availH;
                MaxHeight = Math.Min(targetMaxH, availH);
            }
            else
            {
                MaxHeight = targetMaxH;
            }
            if (workArea.Width > 0)
            {
                double availW = Math.Max(480, workArea.Width - 24);
                if (MinWidth > availW) MinWidth = availW;
                MaxWidth = availW;
                if (Width > availW) Width = availW;
            }
        }
        catch { }
    }

    private void Finish()
    {
        App.OnConsentChanged();
        if (System.Windows.Interop.ComponentDispatcher.IsThreadModal)
        {
            try { DialogResult = true; } catch { }
        }
    }

    /// <summary>Closing the window without choosing keeps the app undecided (nothing is collected, Free behavior).</summary>
    public static bool ShowFirstRun()
    {
        var store = EditionService.Instance.Consent;
        if (store.HasDecided && !store.NeedsReconsent) return false;
        return new ConsentWindow(store, isFirstRunMode: true).ShowDialog() == true;
    }

    /// <summary>Re-opens the edition &amp; region screen from Settings or the upgrade prompt.</summary>
    public static void ShowFromSettings(Window? owner)
    {
        var w = new ConsentWindow(EditionService.Instance.Consent, isFirstRunMode: false);
        if (owner is { IsLoaded: true })
        {
            w.Owner = owner;
            w.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        w.ShowDialog();
    }
}
