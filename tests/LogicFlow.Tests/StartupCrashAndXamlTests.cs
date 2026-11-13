using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using LogicFlow.Dashboard;
using LogicFlow.Lazarus;
using LogicFlow.Registry;
using OmniPulse;
using Xunit;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using ListView = System.Windows.Controls.ListView;
using Panel = System.Windows.Controls.Panel;
using Size = System.Windows.Size;

namespace LogicFlow.Tests;

[Collection("WpfHeadlessExecution")]
public class StartupCrashAndXamlTests
{
    [Fact]
    public void CrashGuard_ExtractExceptionDetails_RecursivelyCapturesNestedExceptionsAndHResults()
    {
        var leafException = new InvalidOperationException("Inner leaf failure") { HResult = unchecked((int)0x80004005) };
        var midException = new ArgumentException("Middle wrapper", leafException) { HResult = unchecked((int)0x80070057) };
        var topException = new Exception("Top level exception", midException) { HResult = unchecked((int)0x80131500) };

        var (hierarchy, fullInnerMessage, xamlInfo, firstInnerType) = CrashGuard.ExtractExceptionDetails(topException);

        Assert.Equal(2, hierarchy.Count);
        Assert.Contains("0x80070057", hierarchy[0]);
        Assert.Contains("Middle wrapper", hierarchy[0]);
        Assert.Contains("0x80004005", hierarchy[1]);
        Assert.Contains("Inner leaf failure", hierarchy[1]);
        Assert.Equal(typeof(ArgumentException).FullName, firstInnerType);
        Assert.Contains("Middle wrapper", fullInnerMessage);
        Assert.Contains("Inner leaf failure", fullInnerMessage);
    }

    [Fact]
    public void CrashGuard_ExtractExceptionDetails_CapturesAggregateExceptionFlattened()
    {
        var ex1 = new InvalidOperationException("First error") { HResult = unchecked((int)0x80131509) };
        var ex2 = new FormatException("Second error") { HResult = unchecked((int)0x80131537) };
        var aggregate = new AggregateException("Multiple faults", ex1, ex2);

        var (hierarchy, fullInnerMessage, xamlInfo, firstInnerType) = CrashGuard.ExtractExceptionDetails(aggregate);

        Assert.True(hierarchy.Count >= 2);
        Assert.Contains("First error", fullInnerMessage);
        Assert.Contains("Second error", fullInnerMessage);
    }

    [Fact]
    public void CrashGuard_ExtractExceptionDetails_CapturesXamlParseExceptionInfo()
    {
        var xamlEx = new XamlParseException("StaticResource not found", 654, 45, new InvalidOperationException("Resource not defined"));

        var (hierarchy, fullInnerMessage, xamlInfo, firstInnerType) = CrashGuard.ExtractExceptionDetails(xamlEx);

        Assert.NotNull(xamlInfo);
        Assert.Contains("LineNumber: 654", xamlInfo);
        Assert.Contains("LinePosition: 45", xamlInfo);
    }

    [Fact]
    public void CrashGuard_ExtractExceptionDetails_CapturesNestedXamlParseExceptionWithKeyAndBaseUri()
    {
        var innerXaml = new XamlParseException("Provide value threw an exception", 128, 19, new InvalidOperationException("Missing resource"));
        typeof(XamlParseException).GetProperty("KeyContext", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.SetValue(innerXaml, "GlassPanel");
        typeof(XamlParseException).GetProperty("BaseUri", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.SetValue(innerXaml, new Uri("pack://application:,,,/MainWindow.xaml"));
        var wrapper = new TargetInvocationException("Exception has been thrown by the target of an invocation.", innerXaml);

        var (hierarchy, fullInnerMessage, xamlInfo, firstInnerType) = CrashGuard.ExtractExceptionDetails(wrapper);

        Assert.NotNull(xamlInfo);
        Assert.Contains("LineNumber: 128", xamlInfo);
        Assert.Contains("LinePosition: 19", xamlInfo);
        Assert.Contains("KeyContext: 'GlassPanel'", xamlInfo);
        Assert.Contains("BaseUri: 'pack://application:,,,/MainWindow.xaml'", xamlInfo);
        Assert.Contains("[XAML Line 128:19, Key='GlassPanel', Uri='pack://application:,,,/MainWindow.xaml']", fullInnerMessage);
        Assert.Equal(typeof(XamlParseException).FullName, firstInnerType);
    }

    [Fact]
    public void OmniPulse_Assembly_DoesNotReferenceWpfOrWinFormsFrameworks()
    {
        var referencedNames = typeof(CrashGuard).Assembly
            .GetReferencedAssemblies()
            .Select(a => a.Name ?? "")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.DoesNotContain("PresentationFramework", referencedNames);
        Assert.DoesNotContain("PresentationCore", referencedNames);
        Assert.DoesNotContain("WindowsBase", referencedNames);
        Assert.DoesNotContain("System.Xaml", referencedNames);
        Assert.DoesNotContain("System.Windows.Forms", referencedNames);
    }

    [Fact]
    public void CrashGuard_ExtractExceptionDetails_CapturesSystemXamlExceptionInfo()
    {
        var xamlObjEx = new System.Xaml.XamlException("Failed to create object", null, 312, 27);
        var (hierarchy, fullInnerMessage, xamlInfo, firstInnerType) = CrashGuard.ExtractExceptionDetails(xamlObjEx);

        Assert.NotNull(xamlInfo);
        Assert.Contains("LineNumber: 312", xamlInfo);
        Assert.Contains("LinePosition: 27", xamlInfo);
        Assert.Empty(hierarchy);
        Assert.Null(firstInnerType);
        Assert.Equal(string.Empty, fullInnerMessage);
    }

    [Fact]
    public void Lazarus_AllFileTypeDescriptionsAndSignatures_AvoidDuplicateExtSuffixes()
    {
        string[] knownExtensions =
        [
            "png", "jpg", "jpeg", "bmp", "gif", "webp", "ico", "pdf", "docx", "xlsx",
            "pptx", "doc", "txt", "json", "xml", "csv", "log", "zip", "7z", "rar",
            "mp4", "avi", "mp3", "wav", "flac", "sqlite", "db", "riff", "ogg", "rtf"
        ];

        foreach (var ext in knownExtensions)
        {
            string desc = FileCarver.DetermineFileTypeDescription(ext);
            Assert.False(desc.Contains(" (.", StringComparison.Ordinal),
                $"Extension '{ext}' returned duplicate suffix in '{desc}'");
        }

        Assert.Equal("SQLite 3 Database", FileCarver.DetermineFileTypeDescription("sqlite"));
        Assert.Equal("SQLite 3 Database", FileCarver.DetermineFileTypeDescription("db"));

        foreach (var sig in FileCarver.Signatures)
        {
            Assert.False(sig.Description.Contains(" (.", StringComparison.Ordinal),
                $"Signature '{sig.Extension}' returned duplicate suffix in '{sig.Description}'");
        }

        // Defensive UI stripping on legacy/serialized CarvedFileHeader values
        var legacyItem = new CarvedFileItem
        {
            Header = new CarvedFileHeader { Extension = "sqlite", FileType = "SQLite Database (.sqlite)" }
        };
        Assert.Equal("SQLite Database", legacyItem.FileType);
    }

    [Fact]
    public void AllStaticResourceReferences_InMainWindowAndAppXaml_AreResolved()
    {
        // Programmatically parse all x:Key in App.xaml, GlassmorphicTheme.xaml, and MainWindow.xaml
        var solutionRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var srcDir = Path.Combine(solutionRoot, "src");

        var allKeys = new HashSet<string>(StringComparer.Ordinal);
        var xamlFiles = Directory.GetFiles(srcDir, "*.xaml", SearchOption.AllDirectories);

        foreach (var file in xamlFiles)
        {
            var content = File.ReadAllText(file);
            var matches = Regex.Matches(content, @"x:Key=""([^""]+)""");
            foreach (Match m in matches)
            {
                allKeys.Add(m.Groups[1].Value.Trim());
            }
        }

        var missing = new List<string>();
        foreach (var file in xamlFiles)
        {
            var content = File.ReadAllText(file);
            var resMatches = Regex.Matches(content, @"\{StaticResource\s+([^}]+)\}");
            foreach (Match m in resMatches)
            {
                var key = m.Groups[1].Value.Trim();
                if (!allKeys.Contains(key))
                {
                    missing.Add($"{Path.GetFileName(file)} -> {key}");
                }
            }
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void MainWindow_BamlParsing_InitializesSuccessfullyInStaThread()
    {
        Exception? threadEx = null;

        var staThread = new Thread(() =>
        {
            MainWindow? window = null;
            try
            {
                if (System.Windows.Application.Current == null)
                {
                    var app = new LogicFlow.Dashboard.App();
                    app.InitializeComponent();
                }

                // 1. Verify Dialogs.Shield pack URI loads from LogicFlow assembly under testhost
                var shield64 = Dialogs.Shield(64);
                Assert.NotNull(shield64);
                Assert.Equal(64, shield64.PixelWidth);

                // 2. Verify SplashWindow BAML, dimensions (520x340), dynamic tier/version labels
                var splash = new SplashWindow();
                Assert.Equal(520, splash.Width);
                Assert.Equal(340, splash.Height);
                var tierBadgeText = splash.FindName("TierBadgeText") as System.Windows.Controls.TextBlock;
                var versionLabel = splash.FindName("VersionLabel") as System.Windows.Controls.TextBlock;
                Assert.NotNull(tierBadgeText);
                Assert.NotNull(versionLabel);
                splash.Close();

                // 3. Verify ConsentWindow BAML & pack URIs load under testhost + 3-step wizard state
                var tempConsentDir = Path.Combine(Path.GetTempPath(), "lf-wiz-test-" + Guid.NewGuid().ToString("N"));
                try
                {
                    var testStore = new ConsentStore(tempConsentDir, (_, _) => null);
                    var consentWin = new ConsentWindow(testStore, isFirstRunMode: true);
                    Assert.NotNull(consentWin.FindName("RbFree"));
                    Assert.NotNull(consentWin.FindName("RbCommunity"));
                    Assert.NotNull(consentWin.FindName("RbPro"));
                    Assert.NotNull(consentWin.FindName("ChkStandard"));
                    Assert.NotNull(consentWin.FindName("ChkExtended"));
                    Assert.NotNull(consentWin.FindName("ChkEula"));
                    Assert.Equal(1, consentWin.CurrentStep);

                    var step1 = consentWin.FindName("Step1RegionPanel") as UIElement;
                    var step2 = consentWin.FindName("Step2EditionPanel") as UIElement;
                    var step3 = consentWin.FindName("Step3PreferencesPanel") as UIElement;
                    Assert.NotNull(step1);
                    Assert.NotNull(step2);
                    Assert.NotNull(step3);
                    Assert.Equal(Visibility.Visible, step1!.Visibility);
                    Assert.Equal(Visibility.Collapsed, step2!.Visibility);
                    Assert.Equal(Visibility.Collapsed, step3!.Visibility);

                    var cmbRegion = consentWin.FindName("CmbRegion") as System.Windows.Controls.ComboBox;
                    var chkExtended = consentWin.FindName("ChkExtended") as System.Windows.Controls.CheckBox;
                    Assert.NotNull(cmbRegion);
                    Assert.NotNull(chkExtended);
                    Assert.Equal(12, cmbRegion!.Items.Count);

                    // Select strict region (Canada -> index 1) -> ChkExtended unchecked, enabled
                    cmbRegion.SelectedIndex = 1;
                    Assert.False(chkExtended!.IsChecked == true);
                    Assert.True(chkExtended.IsEnabled);

                    // Select non-strict region (UnitedStates -> index 0) -> ChkExtended pre-checked, enabled
                    cmbRegion.SelectedIndex = 0;
                    Assert.True(chkExtended.IsChecked == true);
                    Assert.True(chkExtended.IsEnabled);

                    // Step navigation
                    consentWin.GoToStep(2);
                    Assert.Equal(2, consentWin.CurrentStep);
                    Assert.Equal(Visibility.Collapsed, step1.Visibility);
                    Assert.Equal(Visibility.Visible, step2.Visibility);

                    consentWin.GoToStep(3);
                    Assert.Equal(3, consentWin.CurrentStep);
                    Assert.Equal(Visibility.Visible, step3.Visibility);

                    var chkStartWin = consentWin.FindName("ChkPrefStartWithWindows") as System.Windows.Controls.CheckBox;
                    var chkTray = consentWin.FindName("ChkPrefMinimizeToTray") as System.Windows.Controls.CheckBox;
                    var chkUpdates = consentWin.FindName("ChkPrefCheckUpdates") as System.Windows.Controls.CheckBox;
                    var chkSmartScan = consentWin.FindName("ChkPrefScanSmart") as System.Windows.Controls.CheckBox;
                    var chkShield = consentWin.FindName("ChkPrefTelemetryBlocking") as System.Windows.Controls.CheckBox;
                    Assert.False(chkStartWin!.IsChecked == true);
                    Assert.True(chkTray!.IsChecked == true);
                    Assert.True(chkUpdates!.IsChecked == true);
                    Assert.True(chkSmartScan!.IsChecked == true);
                    Assert.False(chkShield!.IsChecked == true);

                    consentWin.Close();

                    // Verify upgrading from Free -> Community in a non-strict region (US) pre-checks ChkExtended
                    testStore.Apply(EditionChoice.Free, PrivacyRegion.UnitedStates, false, false, "1.0", "sha");
                    var settingsWin = new ConsentWindow(testStore, isFirstRunMode: false);
                    var rbCommunity = settingsWin.FindName("RbCommunity") as System.Windows.Controls.RadioButton;
                    var settingsChkExtended = settingsWin.FindName("ChkExtended") as System.Windows.Controls.CheckBox;
                    Assert.NotNull(rbCommunity);
                    Assert.NotNull(settingsChkExtended);
                    settingsWin.GoToStep(2);
                    rbCommunity!.IsChecked = true;
                    settingsWin.ApplyRegionDefaults(preserveStoredIfSameRegion: true);
                    Assert.True(settingsChkExtended!.IsChecked == true);
                    settingsWin.Close();
                }
                finally
                {
                    try { Directory.Delete(tempConsentDir, true); } catch { }
                }

                // 4. Verify MainWindow BAML, removed VoiceAgent, Settings privacy controls, and StartInTray() without Show()
                window = new MainWindow();
                Assert.NotNull(window);
                Assert.NotNull(window.Content);
                Assert.NotNull(window.FindName("NavDashboard"));
                Assert.Null(window.FindName("NavVoiceAgent"));
                Assert.NotNull(window.FindName("SettingShareStandard"));
                Assert.NotNull(window.FindName("SettingShareExtended"));
                Assert.NotNull(window.FindName("TelemetryStatusText"));

                // Verify App.ShouldTerminateOnUnhandledUiException BEFORE StartInTray()
                Assert.True(App.ShouldTerminateOnUnhandledUiException(null, isSilentStartup: false, out bool dialogNullInteractive));
                Assert.True(dialogNullInteractive);
                Assert.True(App.ShouldTerminateOnUnhandledUiException(null, isSilentStartup: true, out bool dialogNullSilent));
                Assert.False(dialogNullSilent);
                Assert.False(window.IsLoaded);
                Assert.False(window.IsTrayResident);
                Assert.True(App.ShouldTerminateOnUnhandledUiException(window, isSilentStartup: false, out bool dialogPreLoad));
                Assert.True(dialogPreLoad);
                Assert.True(App.ShouldTerminateOnUnhandledUiException(window, isSilentStartup: true, out bool dialogPreLoadSilent));
                Assert.False(dialogPreLoadSilent);

                window.StartInTray();
                Assert.False(window.IsLoaded);
                Assert.True(window.IsTrayResident);
                Assert.False(App.ShouldTerminateOnUnhandledUiException(window, isSilentStartup: true, out bool dialogTrayResident));
                Assert.False(dialogTrayResident);
                var hwnd = new System.Windows.Interop.WindowInteropHelper(window).Handle;
                Assert.NotEqual(IntPtr.Zero, hwnd);
                var trayField = typeof(MainWindow).GetField("_trayManager", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                Assert.NotNull(trayField);
                var trayInstance = trayField!.GetValue(window) as IDisposable;
                Assert.NotNull(trayInstance);
                trayInstance!.Dispose();

                // 5. Verify Lazarus CarvedFilesListView 150%-scale column floors and Registry layout headlessly
                var tempSettingsFile = Path.Combine(Path.GetTempPath(), "lf-sta-ui-" + Guid.NewGuid().ToString("N") + ".json");
                SettingsManager.OverrideSettingsPath = tempSettingsFile;
                SettingsManager.ClearCache();
                try
                {
                    VerifyAndOptionallyRenderPopulatedViews(window);
                }
                finally
                {
                    SettingsManager.OverrideSettingsPath = null;
                    SettingsManager.ClearCache();
                    if (System.Windows.Application.Current != null)
                    {
                        MainWindow.ApplyPaletteToResources(
                            System.Windows.Application.Current.Resources,
                            new UserSettings { Theme = ThemeMode.Dark, Accent = AccentColor.Cyan, UiScale = 1.0 });
                    }
                    try { if (File.Exists(tempSettingsFile)) File.Delete(tempSettingsFile); } catch { }
                }
            }
            catch (Exception ex)
            {
                threadEx = ex;
            }
            finally
            {
                try { window?.Close(); } catch { }
                try { System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown(); } catch { }
            }
        });

        staThread.SetApartmentState(ApartmentState.STA);
        staThread.Start();
        staThread.Join(TimeSpan.FromSeconds(45));

        if (threadEx != null)
        {
            throw new Exception($"Failed to initialize WPF windows in STA thread: {threadEx.Message}", threadEx);
        }
    }

    private static void VerifyAndOptionallyRenderPopulatedViews(MainWindow window)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
        var t = typeof(MainWindow);

        var rootElement = Assert.IsAssignableFrom<FrameworkElement>(window.Content);
        window.Content = null;
        window.Width = 1280;
        window.Height = 820;
        var host = new Border
        {
            Width = 1280,
            Height = 820,
            Background = new SolidColorBrush(Color.FromRgb(0x0A, 0x0E, 0x1A)),
            Child = rootElement
        };

        var carvedItems = new List<CarvedFileItem>
        {
            new()
            {
                DriveSource = @"C:\",
                Header = new CarvedFileHeader
                {
                    FileName = "architecture_diagram_v4.png",
                    Extension = "png",
                    FileType = "PNG Image",
                    Category = "Images",
                    ByteOffset = 0x04A28000,
                    EstimatedSizeBytes = 2_485_120,
                    Confidence = "100% Verified",
                    RecoveryMethod = "NTFS MFT Resident/Runlist",
                    OriginalPath = @"C:\Users\Alex\Pictures\architecture_diagram_v4.png",
                    ImageWidth = 1920,
                    ImageHeight = 1080
                }
            },
            new()
            {
                DriveSource = @"C:\",
                Header = new CarvedFileHeader
                {
                    FileName = "Q4_financial_summary.pdf",
                    Extension = "pdf",
                    FileType = "PDF Document",
                    Category = "Documents",
                    ByteOffset = 0x0819C000,
                    EstimatedSizeBytes = 1_142_948,
                    Confidence = "100% Intact",
                    RecoveryMethod = "Recycle Bin ($I/$R)",
                    OriginalPath = @"C:\Users\Alex\Documents\Q4_financial_summary.pdf"
                }
            },
            new()
            {
                DriveSource = @"C:\",
                Header = new CarvedFileHeader
                {
                    FileName = "release_symbols_backup.zip",
                    Extension = "zip",
                    FileType = "ZIP Archive",
                    Category = "Archives",
                    ByteOffset = 0x11C40000,
                    EstimatedSizeBytes = 8_912_896,
                    Confidence = "High Confidence",
                    RecoveryMethod = "Raw Sector Carving"
                }
            },
            new()
            {
                DriveSource = @"C:\",
                Header = new CarvedFileHeader
                {
                    FileName = "telemetry_local_cache.sqlite",
                    Extension = "sqlite",
                    FileType = "SQLite 3 Database",
                    Category = "Databases",
                    ByteOffset = 0x19F02000,
                    EstimatedSizeBytes = 524_288,
                    Confidence = "High",
                    RecoveryMethod = "Comprehensive Deep Scan"
                }
            }
        };

        if (t.GetField("_allCarvedItems", flags)?.GetValue(window) is IList<CarvedFileItem> allList)
        {
            allList.Clear();
            foreach (var item in carvedItems) allList.Add(item);
        }

        var carvedLv = Assert.IsType<ListView>(window.FindName("CarvedFilesListView"));
        carvedLv.ItemsSource = new ObservableCollection<CarvedFileItem>(carvedItems);
        Assert.IsType<Border>(window.FindName("LazarusRecoveryPanel")).Visibility = Visibility.Visible;
        Assert.IsType<TextBlock>(window.FindName("LazarusTelemetryText")).Text =
            "Discovered: 4 signatures | Recoverable Size: 12.46 MB | Elapsed: 0.4s";
        Assert.IsType<TextBlock>(window.FindName("LazarusSelectedSummary")).Text =
            "Selected: 4 of 4 files (12.46 MB)";

        var driveList = Assert.IsType<ItemsControl>(window.FindName("DriveList"));
        var makeDriveCard = t.GetMethod("MakeLazarusDriveCard", flags);
        if (makeDriveCard != null && driveList.Items.Count == 0)
        {
            foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady))
            {
                long used = d.TotalSize - d.TotalFreeSpace;
                double pct = d.TotalSize > 0 ? (double)used / d.TotalSize * 100.0 : 0.0;
                string colorKey = pct > 90 ? "DangerRedBrush" : pct > 70 ? "WarningAmberBrush" : "SuccessGreenBrush";
                var card = makeDriveCard.Invoke(window, [d.Name, d.DriveType.ToString(), d.VolumeLabel, d.TotalSize, d.TotalFreeSpace, pct, colorKey]);
                if (card != null) driveList.Items.Add(card);
            }
        }

        var regResult = new RegistryScanResult
        {
            ScannedAt = DateTimeOffset.UtcNow,
            ScanDuration = TimeSpan.FromMilliseconds(320),
            OrphanedSoftwareKeys =
            [
                new RegistryIssue
                {
                    Path = @"Software\OldUpdaterV2",
                    FullRegistryPath = @"HKCU\Software\OldUpdaterV2",
                    Type = RegistryIssueType.OrphanedKey,
                    Description = @"Uninstalled application directory C:\Program Files\OldUpdaterV2 no longer exists",
                    Severity = IssueSeverity.Low,
                    IsSafeToFix = true,
                    IsSelected = true
                },
                new RegistryIssue
                {
                    Path = @"Software\LegacyCodecPack",
                    FullRegistryPath = @"HKLM\SOFTWARE\LegacyCodecPack",
                    Type = RegistryIssueType.OrphanedKey,
                    Description = "Dangling software key referencing missing uninstaller binary",
                    Severity = IssueSeverity.Low,
                    IsSafeToFix = true,
                    IsSelected = true
                }
            ],
            BrokenFileAssociations =
            [
                new RegistryIssue
                {
                    Path = @".oldproj",
                    FullRegistryPath = @"HKCR\.oldproj",
                    Type = RegistryIssueType.BrokenFileAssociation,
                    Description = @"Extension .oldproj references missing ProgID OldStudio.Project.1",
                    Severity = IssueSeverity.Low,
                    IsSafeToFix = true,
                    IsSelected = true
                }
            ],
            InvalidPaths =
            [
                new RegistryIssue
                {
                    Path = @"App Paths\obsolete.exe",
                    FullRegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\obsolete.exe",
                    Type = RegistryIssueType.InvalidPath,
                    Description = @"Application path target C:\Tools\Obsolete\obsolete.exe no longer exists",
                    Severity = IssueSeverity.Low,
                    IsSafeToFix = true,
                    IsSelected = true
                }
            ]
        };

        var renderRegMethod = t.GetMethod("RenderRegistryResults", flags)!;
        var toggleOrphansMethod = t.GetMethod("OnToggleOrphans", flags)!;
        var applyVisualMethod = t.GetMethod("ApplyVisualSettings", flags)!;
        var adjustCarvedMethod = t.GetMethod("AdjustCarvedFilesColumns", flags)!;
        var showPageMethod = t.GetMethod("ShowPage", flags)!;

        var pageLazarus = Assert.IsType<ScrollViewer>(window.FindName("PageLazarus"));
        var pageRegistry = Assert.IsType<ScrollViewer>(window.FindName("PageRegistry"));
        var navLazarus = Assert.IsType<Button>(window.FindName("NavLazarus"));
        var navRegistry = Assert.IsType<Button>(window.FindName("NavRegistry"));
        var orphanList = Assert.IsType<ItemsControl>(window.FindName("OrphanList"));
        var winSettings = Assert.IsType<UserSettings>(t.GetField("_settings", flags)!.GetValue(window));

        static void LayoutHost(Border border)
        {
            border.Measure(new Size(1280, 820));
            border.Arrange(new Rect(0, 0, 1280, 820));
            border.UpdateLayout();
        }

        static void ActivateExclusivePage(MainWindow win, ScrollViewer target, string title, Button activeBtn, MethodInfo showPage)
        {
            if (target.Parent is Panel pagesPanel)
            {
                foreach (UIElement child in pagesPanel.Children)
                {
                    if (child is ScrollViewer sv && !ReferenceEquals(sv, target))
                    {
                        sv.Visibility = Visibility.Collapsed;
                    }
                }
            }
            if (win.FindName("NavDashboard") is Button navDash && !ReferenceEquals(navDash, activeBtn))
            {
                navDash.Style = (Style)win.FindResource("NavButton");
            }
            showPage.Invoke(win, [target, title, activeBtn]);
        }

        // Verify 150% UI scale Lazarus column widths never crush below readable floors
        winSettings.Theme = ThemeMode.Dark;
        winSettings.UiScale = 1.5;
        winSettings.EnableAnimations = false;
        applyVisualMethod.Invoke(window, null);
        ActivateExclusivePage(window, pageLazarus, "Lazarus — Data Recovery", navLazarus, showPageMethod);
        LayoutHost(host);
        adjustCarvedMethod.Invoke(window, null);
        LayoutHost(host);

        var gv = Assert.IsType<GridView>(carvedLv.View);
        Assert.Equal(7, gv.Columns.Count);
        Assert.True(gv.Columns[0].Width >= 32.0, $"Expected checkbox column >= 32px at 150% scale, got {gv.Columns[0].Width}");
        Assert.True(gv.Columns[1].Width >= 224.0, $"Expected file column >= 224px at 150% scale, got {gv.Columns[1].Width}");
        Assert.True(gv.Columns[2].Width >= 168.0, $"Expected format column >= 168px at 150% scale, got {gv.Columns[2].Width}");
        Assert.True(gv.Columns[2].Width >= 200.0, $"Expected format column >= 200px so 'SQLite 3 Database' + badge never truncates, got {gv.Columns[2].Width}");
        Assert.True(gv.Columns[3].Width >= 102.0, $"Expected offset column >= 102px at 150% scale, got {gv.Columns[3].Width}");
        Assert.True(gv.Columns[4].Width >= 92.0, $"Expected size column >= 92px at 150% scale, got {gv.Columns[4].Width}");
        Assert.True(gv.Columns[5].Width >= 148.0, $"Expected confidence column >= 148px at 150% scale, got {gv.Columns[5].Width}");
        Assert.True(gv.Columns[6].Width >= 92.0, $"Expected preview column >= 92px at 150% scale, got {gv.Columns[6].Width}");

        // Verify DirectWrite cell template measurement across ALL FileCarver signatures & descriptions fits inside gv.Columns[2].Width
        var formatCellTemplate = Assert.IsType<DataTemplate>(gv.Columns[2].CellTemplate);
        var allFormatPairs = FileCarver.Signatures
            .Select(s => (Ext: s.Extension, Desc: s.Description))
            .Concat(new[]
            {
                "png", "jpg", "bmp", "gif", "webp", "ico", "pdf", "docx", "xlsx", "pptx",
                "doc", "txt", "json", "xml", "csv", "log", "zip", "7z", "rar", "mp4",
                "avi", "mp3", "wav", "flac", "sqlite", "db"
            }.Select(ext => (Ext: ext, Desc: FileCarver.DetermineFileTypeDescription(ext))))
            .Distinct();

        foreach (var pair in allFormatPairs)
        {
            var cellContent = Assert.IsAssignableFrom<FrameworkElement>(formatCellTemplate.LoadContent());
            cellContent.Resources.MergedDictionaries.Add(host.Resources);
            cellContent.DataContext = new CarvedFileItem
            {
                Header = new CarvedFileHeader { Extension = pair.Ext, FileType = pair.Desc }
            };
            cellContent.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Assert.True(
                cellContent.DesiredSize.Width + 16.0 <= gv.Columns[2].Width,
                $"Format cell '{pair.Desc}' [{pair.Ext.ToUpperInvariant()}] measured {cellContent.DesiredSize.Width:F1}px (+16px pad) > {gv.Columns[2].Width:F1}px column width");
        }

        // Non-MainWindow (e.g. SplashWindow) MUST NOT be treated as an initialized MainWindow host
        var dummySplashWindow = new Window();
        Assert.True(App.ShouldTerminateOnUnhandledUiException(dummySplashWindow, isSilentStartup: false, out bool dialogSplash));
        Assert.True(dialogSplash);
        dummySplashWindow.Close();

        host.Child = null;
        window.Content = rootElement;

        string? outDir = Environment.GetEnvironmentVariable("LF_RENDER_UI_DIR");
        if (!string.IsNullOrWhiteSpace(outDir) && Directory.Exists(outDir))
        {
            var configs = new (string Prefix, ThemeMode Theme, double Scale, int LazarusSteps, int RegSteps)[]
            {
                ("08_populated_dark_scale150", ThemeMode.Dark, 1.5, 4, 4),
                ("08_populated_dark", ThemeMode.Dark, 1.0, 2, 2),
                ("08_populated_light", ThemeMode.Light, 1.0, 2, 2)
            };

            foreach (var cfg in configs)
            {
                var s = SettingsManager.Load();
                s.Theme = cfg.Theme;
                s.UiScale = cfg.Scale;
                s.EnableAnimations = false;
                s.AutoScanOnStartup = false;
                SettingsManager.Save();
                if (Application.Current != null)
                {
                    MainWindow.ApplyPaletteToResources(Application.Current.Resources, s);
                }

                var rWin = new MainWindow();
                var rSettings = Assert.IsType<UserSettings>(t.GetField("_settings", flags)!.GetValue(rWin));
                rSettings.Theme = cfg.Theme;
                rSettings.UiScale = cfg.Scale;
                rSettings.EnableAnimations = false;
                applyVisualMethod.Invoke(rWin, null);

                var rRoot = Assert.IsAssignableFrom<FrameworkElement>(rWin.Content);
                rWin.Content = null;
                var rHost = new Border
                {
                    Width = 1280,
                    Height = 820
                };
                rHost.Resources.MergedDictionaries.Add(rWin.Resources);
                MainWindow.ApplyPaletteToResources(rHost.Resources, rSettings);
                rHost.Background = rHost.Resources["BrandDarkBrush"] as Brush
                    ?? new SolidColorBrush(cfg.Theme == ThemeMode.Light ? Color.FromRgb(0xF8, 0xFA, 0xFC) : Color.FromRgb(0x0A, 0x0E, 0x1A));
                rHost.Child = rRoot;

                var freshCarved = carvedItems.Select(ci => new CarvedFileItem { DriveSource = ci.DriveSource, Header = ci.Header }).ToList();
                if (t.GetField("_allCarvedItems", flags)?.GetValue(rWin) is IList<CarvedFileItem> rAll)
                {
                    rAll.Clear();
                    foreach (var item in freshCarved) rAll.Add(item);
                }
                var rCarvedLv = Assert.IsType<ListView>(rWin.FindName("CarvedFilesListView"));
                rCarvedLv.ItemsSource = new ObservableCollection<CarvedFileItem>(freshCarved);
                Assert.IsType<Border>(rWin.FindName("LazarusRecoveryPanel")).Visibility = Visibility.Visible;
                Assert.IsType<TextBlock>(rWin.FindName("LazarusTelemetryText")).Text =
                    "Discovered: 4 signatures | Recoverable Size: 12.46 MB | Elapsed: 0.4s";
                Assert.IsType<TextBlock>(rWin.FindName("LazarusSelectedSummary")).Text =
                    "Selected: 4 of 4 files (12.46 MB)";

                var rDriveList = Assert.IsType<ItemsControl>(rWin.FindName("DriveList"));
                if (makeDriveCard != null && rDriveList.Items.Count == 0)
                {
                    foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady))
                    {
                        long used = d.TotalSize - d.TotalFreeSpace;
                        double pct = d.TotalSize > 0 ? (double)used / d.TotalSize * 100.0 : 0.0;
                        string colorKey = pct > 90 ? "DangerRedBrush" : pct > 70 ? "WarningAmberBrush" : "SuccessGreenBrush";
                        var card = makeDriveCard.Invoke(rWin, [d.Name, d.DriveType.ToString(), d.VolumeLabel, d.TotalSize, d.TotalFreeSpace, pct, colorKey]);
                        if (card != null) rDriveList.Items.Add(card);
                    }
                }

                var rPageLaz = Assert.IsType<ScrollViewer>(rWin.FindName("PageLazarus"));
                var rPageReg = Assert.IsType<ScrollViewer>(rWin.FindName("PageRegistry"));
                var rNavLaz = Assert.IsType<Button>(rWin.FindName("NavLazarus"));
                var rNavReg = Assert.IsType<Button>(rWin.FindName("NavRegistry"));
                var rOrphanList = Assert.IsType<ItemsControl>(rWin.FindName("OrphanList"));

                renderRegMethod.Invoke(rWin, [regResult]);
                if (rOrphanList.Visibility != Visibility.Visible)
                {
                    toggleOrphansMethod.Invoke(rWin, [new Button(), new RoutedEventArgs()]);
                }

                ActivateExclusivePage(rWin, rPageLaz, "Lazarus — Data Recovery", rNavLaz, showPageMethod);
                LayoutHost(rHost);
                adjustCarvedMethod.Invoke(rWin, null);
                LayoutHost(rHost);

                double lazMax = Math.Max(0, rPageLaz.ExtentHeight - rPageLaz.ViewportHeight);
                for (int i = 0; i < cfg.LazarusSteps; i++)
                {
                    double offset = cfg.LazarusSteps <= 1 ? 0 : (lazMax * i) / (cfg.LazarusSteps - 1);
                    rPageLaz.ScrollToVerticalOffset(offset);
                    LayoutHost(rHost);
                    adjustCarvedMethod.Invoke(rWin, null);
                    LayoutHost(rHost);
                    SaveHostPng(rHost, Path.Combine(outDir, $"{cfg.Prefix}_07_lazarus_s{i}.png"));
                }

                ActivateExclusivePage(rWin, rPageReg, "Registry Surgeon", rNavReg, showPageMethod);
                LayoutHost(rHost);

                double regMax = Math.Max(0, rPageReg.ExtentHeight - rPageReg.ViewportHeight);
                for (int i = 0; i < cfg.RegSteps; i++)
                {
                    double offset = cfg.RegSteps <= 1 ? 0 : (regMax * i) / (cfg.RegSteps - 1);
                    rPageReg.ScrollToVerticalOffset(offset);
                    LayoutHost(rHost);
                    SaveHostPng(rHost, Path.Combine(outDir, $"{cfg.Prefix}_08_registry_s{i}.png"));
                }

                rHost.Child = null;
                rWin.Content = rRoot;
                rWin.Close();
            }
        }
    }

    private static void SaveHostPng(Border host, string path)
    {
        var rtb = new RenderTargetBitmap(1280, 820, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(host);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(path);
        encoder.Save(fs);
    }
}
