using System.Windows;
using System.Windows.Media.Animation;

namespace LogicFlow.Dashboard;

/// <summary>
/// Animated splash screen with progressive loading messages.
/// Initializes core systems and shows branded startup sequence.
/// </summary>
public partial class SplashWindow : Window
{
    private readonly string[] _loadingMessages =
    [
        "Initializing kernel modules...",
        "Loading LogicFlow.Kernel.dll...",
        "Connecting to CryptoEngine (CNG)...",
        "Mounting DiskMonitor driver...",
        "Initializing S.M.A.R.T. subsystem...",
        "Loading Sentinel security engine...",
        "Calibrating Guardian performance monitor...",
        "Activating Lazarus recovery core...",
        "Scanning registry topology...",
        "Validating license (RSA-2048)...",
        "Connecting to LogicFlowAgent service...",
        "Building system profile...",
        "Loading dashboard interface...",
        "Ready."
    ];

    public SplashWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await AnimateStartup();
    }

    private async Task AnimateStartup()
    {
        for (int i = 0; i < _loadingMessages.Length; i++)
        {
            StatusLabel.Text = _loadingMessages[i];

            // Animate progress bar
            var targetWidth = (double)(i + 1) / _loadingMessages.Length * 300;
            var animation = new DoubleAnimation(targetWidth, TimeSpan.FromMilliseconds(180))
            {
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };
            ProgressFill.BeginAnimation(WidthProperty, animation);

            // Fire-and-forget: send first-install baseline during "Building system profile" step
            // Runs entirely in background — never blocks UI, never delays startup
            if (i == 11) // "Building system profile..."
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var pulse = new OmniPulse.PulseClient();
                        await pulse.SendBaselineAsync();
                    }
                    catch { /* Silently fail — will retry on next launch */ }
                });
            }

            // Variable delay to simulate real initialization
            var delay = i switch
            {
                0 => 200,   // Kernel init
                4 => 300,   // SMART
                9 => 250,   // License check
                11 => 400,  // System profile
                13 => 150,  // Ready
                _ => 120
            };
            await Task.Delay(delay);
        }

        await Task.Delay(400); // Brief pause on "Ready"

        // Open main window and close splash
        var main = new MainWindow();
        Application.Current.MainWindow = main;
        main.Show();
        Close();
    }
}
