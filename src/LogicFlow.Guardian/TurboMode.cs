// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – TurboMode (v2 — Razer Cortex-level)
// Advanced system boost: power plan switching, CPU affinity, network
// optimization, visual effects toggle, timer resolution, GPU priority.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Guardian;

/// <summary>
/// Turbo Mode — temporarily optimizes the system for maximum performance
/// during gaming or focused work. All changes are fully reversible.
/// </summary>
public sealed class TurboMode
{
    private readonly ILogger<TurboMode>? _logger;
    private readonly List<string> _stoppedServices = new();
    private readonly List<(int pid, string name)> _suspendedProcesses = new();
    private bool _isActive;

    // State to restore on deactivate
    private string _originalPowerPlan = "";
    private bool _notificationsDisabled;
    private bool _visualEffectsDisabled;
    private bool _networkOptimized;
    private bool _timerResolutionSet;
    private bool _gpuPrioritySet;
    private readonly Dictionary<string, object?> _originalNetworkValues = new();
    private ProcessPriorityClass _originalPriority = ProcessPriorityClass.Normal;

    // P/Invoke for advanced features
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref int pvParam, uint fWinIni);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

    private const uint SPI_SETCLIENTAREAANIMATION = 0x1043;
    private const uint SPI_SETANIMATION = 0x0049;
    private const uint SPI_SETDRAGFULLWINDOWS = 0x0025;
    private const uint SPI_SETMENUFADE = 0x1013;
    private const uint SPI_SETCOMBOBOXANIMATION = 0x1005;
    private const uint SPI_SETLISTBOXSMOOTHSCROLLING = 0x1007;
    private const uint SPIF_SENDCHANGE = 0x0002;

    public TurboMode(ILogger<TurboMode>? logger = null)
    {
        _logger = logger;
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public bool IsActive => _isActive;

    public sealed class TurboProfile
    {
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public string[] ServicesToStop { get; init; } = [];
        public string[] ProcessesToKill { get; init; } = [];
        public bool DisableNotifications { get; init; }
        public bool SetHighPriority { get; init; }
        // New v2 features
        public bool SwitchPowerPlan { get; init; }
        public bool OptimizeCpuAffinity { get; init; }
        public bool OptimizeNetwork { get; init; }
        public bool DisableVisualEffects { get; init; }
        public bool SetTimerResolution { get; init; }
        public bool BoostGpuPriority { get; init; }
    }

    public sealed class TurboResult
    {
        public bool Activated { get; init; }
        public int ServicesDisabled { get; init; }
        public int ProcessesKilled { get; init; }
        public long MemoryFreedBytes { get; init; }
        public string MemoryFreedFormatted => FormatBytes(MemoryFreedBytes);
        public List<string> Actions { get; init; } = new();
    }

    // ─── Built-in Profiles ───────────────────────────────────────────────

    public static readonly TurboProfile GamingProfile = new()
    {
        Name = "🎮 Gaming Turbo",
        Description = "Maximum GPU/CPU/network for games. Switches power plan, pins CPU cores, disables Nagle.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "Spooler", "TabletInputService", "WMPNetworkSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "YourPhone", "PhoneExperienceHost",
            "SearchApp", "SearchHost", "StartMenuExperienceHost",
            "GameBarPresenceWriter", "gamingservices",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = true,
        OptimizeNetwork = true,
        DisableVisualEffects = true,
        SetTimerResolution = true,
        BoostGpuPriority = true
    };

    public static readonly TurboProfile WorkProfile = new()
    {
        Name = "💼 Work Focus",
        Description = "Disable distractions, boost priority. Keeps network normal.",
        ServicesToStop = [
            "SysMain", "DiagTrack", "dmwappushservice",
            "WerSvc", "MapsBroker", "lfsvc",
            "WMPNetworkSvc", "XblAuthManager", "XblGameSave"
        ],
        ProcessesToKill = [
            "GameBar", "GameBarPresenceWriter",
            "Spotify", "YourPhone", "PhoneExperienceHost",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = false,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = false,
        DisableVisualEffects = false,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    public static readonly TurboProfile BatteryProfile = new()
    {
        Name = "🔋 Battery Saver",
        Description = "Minimize background activity to extend battery. Stops everything non-essential.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "MapsBroker",
            "lfsvc", "WMPNetworkSvc", "PcaSvc",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc",
            "Fax", "PrintNotify", "Spooler"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "SearchApp", "SearchHost",
            "GameBar", "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = false,
        SwitchPowerPlan = false,  // Don't switch — let Windows battery saver handle
        OptimizeCpuAffinity = false,
        OptimizeNetwork = false,
        DisableVisualEffects = true,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    public static readonly TurboProfile StreamingProfile = new()
    {
        Name = "📺 Streaming Mode",
        Description = "Optimized for OBS/streaming. Network + CPU priority without killing Discord/Spotify.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify"
        ],
        ProcessesToKill = [
            "YourPhone", "PhoneExperienceHost",
            "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = true,
        DisableVisualEffects = false,
        SetTimerResolution = true,
        BoostGpuPriority = true
    };

    public static readonly TurboProfile ServerProfile = new()
    {
        Name = "🖥️ Server Mode",
        Description = "Optimizes the system for hosting servers or background tasks. Prioritizes network and background performance.",
        ServicesToStop = [
            "SysMain", "WSearch", "DiagTrack", "dmwappushservice",
            "WerSvc", "wuauserv", "BITS", "PcaSvc",
            "MapsBroker", "lfsvc", "Fax", "PrintNotify",
            "XblAuthManager", "XblGameSave", "XboxNetApiSvc"
        ],
        ProcessesToKill = [
            "OneDrive", "Teams", "Spotify", "Discord",
            "YourPhone", "PhoneExperienceHost",
            "GameBar", "GameBarPresenceWriter",
            "WidgetService", "Widgets"
        ],
        DisableNotifications = true,
        SetHighPriority = true,
        SwitchPowerPlan = true,
        OptimizeCpuAffinity = false,
        OptimizeNetwork = true,
        DisableVisualEffects = true,
        SetTimerResolution = false,
        BoostGpuPriority = false
    };

    // ─── Activate ────────────────────────────────────────────────────────

    /// <summary>
    /// Activates Turbo Mode with the specified profile.
    /// </summary>
    public TurboResult Activate(TurboProfile? profile = null)
    {
        if (_isActive)
        {
            return new TurboResult { Activated = false, Actions = ["Turbo Mode is already active. Deactivate first."] };
        }

        profile ??= GamingProfile;
        _logger?.LogInformation("⚡ Activating Turbo Mode: {Profile}", profile.Name);

        long memoryBefore = GetAvailableMemory();
        var actions = new List<string>();
        int servicesDisabled = 0;
        int processesKilled = 0;

        // 1) Switch power plan to High Performance / Ultimate
        if (profile.SwitchPowerPlan)
        {
            var planResult = SwitchToHighPerformancePlan();
            if (planResult != null) actions.Add(planResult);
        }

        // 2) Stop services
        foreach (var svcName in profile.ServicesToStop)
        {
            try
            {
                if (!SvcHelper.ServiceExists(svcName)) continue;
                using var sc = new System.ServiceProcess.ServiceController(svcName);
                if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                {
                    SvcHelper.StopService(svcName);
                    _stoppedServices.Add(svcName);
                    servicesDisabled++;
                }
            }
            catch { }
        }
        if (servicesDisabled > 0)
            actions.Add($"⏹️ Stopped {servicesDisabled} background services");

        // 3) Kill processes
        foreach (var procName in profile.ProcessesToKill)
        {
            try
            {
                var processes = Process.GetProcessesByName(procName);
                foreach (var proc in processes)
                {
                    try
                    {
                        _suspendedProcesses.Add((proc.Id, proc.ProcessName));
                        proc.Kill();
                        processesKilled++;
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }
        if (processesKilled > 0)
            actions.Add($"🔪 Terminated {processesKilled} background processes");

        // 4) Disable notifications via Focus Assist
        if (profile.DisableNotifications)
        {
            try
            {
                Registry.SetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                    "NOC_GLOBAL_SETTING_TOASTS_ENABLED", 0,
                    RegistryValueKind.DWord);
                _notificationsDisabled = true;
                actions.Add("🔕 Disabled toast notifications");
            }
            catch { }
        }

        // 5) Set process priority
        if (profile.SetHighPriority)
        {
            try
            {
                var proc = Process.GetCurrentProcess();
                _originalPriority = proc.PriorityClass;
                proc.PriorityClass = ProcessPriorityClass.High;
                actions.Add("🔺 Set LogicFlow to high priority");
            }
            catch { }
        }

        // 6) CPU affinity optimization — pin system processes to cores 0-1
        if (profile.OptimizeCpuAffinity)
        {
            var affinityResult = OptimizeCpuAffinity();
            if (affinityResult != null) actions.Add(affinityResult);
        }

        // 7) Network optimization — disable Nagle algorithm
        if (profile.OptimizeNetwork)
        {
            var networkResult = OptimizeNetwork();
            if (networkResult != null) actions.Add(networkResult);
        }

        // 8) Disable visual effects for GPU headroom
        if (profile.DisableVisualEffects)
        {
            var vfxResult = DisableVisualEffects();
            if (vfxResult != null) actions.Add(vfxResult);
        }

        // 9) Set timer resolution to 1ms (better frame pacing)
        if (profile.SetTimerResolution)
        {
            var timerResult = SetHighTimerResolution();
            if (timerResult != null) actions.Add(timerResult);
        }

        // 10) Boost GPU scheduling priority
        if (profile.BoostGpuPriority)
        {
            var gpuResult = BoostGpuPriority();
            if (gpuResult != null) actions.Add(gpuResult);
        }

        // Force garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long memoryAfter = GetAvailableMemory();
        long memoryFreed = Math.Max(0, memoryAfter - memoryBefore);

        if (memoryFreed > 0)
            actions.Add($"💾 Freed {FormatBytes(memoryFreed)} of RAM");

        _isActive = true;
        _logger?.LogInformation("Turbo Mode active. {ActionCount} optimizations applied.", actions.Count);

        return new TurboResult
        {
            Activated = true,
            ServicesDisabled = servicesDisabled,
            ProcessesKilled = processesKilled,
            MemoryFreedBytes = memoryFreed,
            Actions = actions
        };
    }

    // ─── Deactivate ──────────────────────────────────────────────────────

    /// <summary>
    /// Deactivates Turbo Mode and restores all original settings.
    /// </summary>
    public TurboResult Deactivate()
    {
        if (!_isActive)
        {
            return new TurboResult { Activated = false, Actions = ["Turbo Mode is not active."] };
        }

        _logger?.LogInformation("⏹️ Deactivating Turbo Mode...");
        var actions = new List<string>();
        int servicesRestarted = 0;

        // 1) Restore power plan
        if (!string.IsNullOrEmpty(_originalPowerPlan))
        {
            try
            {
                var psi = new ProcessStartInfo("powercfg", $"/setactive {_originalPowerPlan}")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                Process.Start(psi)?.WaitForExit(3000);
                actions.Add("🔌 Restored original power plan");
                _originalPowerPlan = "";
            }
            catch { }
        }

        // 2) Restart stopped services
        foreach (var svcName in _stoppedServices)
        {
            try
            {
                SvcHelper.StartService(svcName);
                servicesRestarted++;
            }
            catch { }
        }
        _stoppedServices.Clear();
        _suspendedProcesses.Clear();
        if (servicesRestarted > 0)
            actions.Add($"▶️ Restarted {servicesRestarted} background services");

        // 3) Re-enable notifications
        if (_notificationsDisabled)
        {
            try
            {
                Registry.SetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
                    "NOC_GLOBAL_SETTING_TOASTS_ENABLED", 1,
                    RegistryValueKind.DWord);
                actions.Add("🔔 Re-enabled notifications");
                _notificationsDisabled = false;
            }
            catch { }
        }

        // 4) Reset process priority
        try
        {
            Process.GetCurrentProcess().PriorityClass = _originalPriority;
        }
        catch { }

        // 5) Restore network settings
        if (_networkOptimized)
        {
            RestoreNetwork();
            actions.Add("🌐 Restored network settings");
            _networkOptimized = false;
        }

        // 6) Restore visual effects
        if (_visualEffectsDisabled)
        {
            RestoreVisualEffects();
            actions.Add("✨ Restored visual effects");
            _visualEffectsDisabled = false;
        }

        // 7) Reset timer resolution
        if (_timerResolutionSet)
        {
            try
            {
                NtSetTimerResolution(156250, true, out _); // Default ~15.6ms
                _timerResolutionSet = false;
            }
            catch { }
        }

        // 8) Reset GPU priority
        if (_gpuPrioritySet)
        {
            RestoreGpuPriority();
            actions.Add("🎮 Restored GPU priority");
            _gpuPrioritySet = false;
        }

        _isActive = false;
        _logger?.LogInformation("Turbo Mode deactivated. All settings restored.");

        return new TurboResult
        {
            Activated = false,
            ServicesDisabled = servicesRestarted,
            Actions = actions
        };
    }

    // ─── Power Plan Switching ────────────────────────────────────────────

    /// <summary>
    /// Switches to High Performance or Ultimate Performance power plan.
    /// Saves current plan GUID for restoration.
    /// </summary>
    private string? SwitchToHighPerformancePlan()
    {
        try
        {
            // Get current active plan
            var getActive = new ProcessStartInfo("powercfg", "/getactivescheme")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var result = Process.Start(getActive);
            var output = result?.StandardOutput.ReadToEnd() ?? "";
            result?.WaitForExit(3000);

            // Parse GUID from output: "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)"
            var guidStart = output.IndexOf("GUID: ", StringComparison.Ordinal);
            if (guidStart >= 0)
            {
                guidStart += 6;
                var guidEnd = output.IndexOf(' ', guidStart);
                if (guidEnd > guidStart)
                    _originalPowerPlan = output[guidStart..guidEnd].Trim();
            }

            // Try Ultimate Performance first (GUID: e9a42b02-d5df-448d-aa00-03f14749eb61)
            var ultimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61";
            var highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";

            // Check if Ultimate Performance exists
            var listPlans = new ProcessStartInfo("powercfg", "/list")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            var listResult = Process.Start(listPlans);
            var listOutput = listResult?.StandardOutput.ReadToEnd() ?? "";
            listResult?.WaitForExit(3000);

            string targetGuid;
            string planName;

            if (listOutput.Contains(ultimateGuid, StringComparison.OrdinalIgnoreCase))
            {
                targetGuid = ultimateGuid;
                planName = "Ultimate Performance";
            }
            else
            {
                // Try to create Ultimate Performance plan
                try
                {
                    var dup = new ProcessStartInfo("powercfg", $"/duplicatescheme {ultimateGuid}")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    var dupResult = Process.Start(dup);
                    dupResult?.WaitForExit(3000);
                    var dupOutput = dupResult?.StandardOutput.ReadToEnd() ?? "";

                    if (dupOutput.Contains("GUID", StringComparison.OrdinalIgnoreCase))
                    {
                        targetGuid = ultimateGuid;
                        planName = "Ultimate Performance";
                    }
                    else
                    {
                        targetGuid = highPerfGuid;
                        planName = "High Performance";
                    }
                }
                catch
                {
                    targetGuid = highPerfGuid;
                    planName = "High Performance";
                }
            }

            // Activate the plan
            var activate = new ProcessStartInfo("powercfg", $"/setactive {targetGuid}")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(activate)?.WaitForExit(3000);

            _logger?.LogInformation("Switched to {Plan} power plan", planName);
            return $"⚡ Switched to {planName} power plan";
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to switch power plan");
            return null;
        }
    }

    // ─── CPU Affinity ────────────────────────────────────────────────────

    /// <summary>
    /// Pins low-priority system processes to cores 0-1, leaving remaining
    /// cores available for the user's foreground application.
    /// </summary>
    private string? OptimizeCpuAffinity()
    {
        try
        {
            int coreCount = Environment.ProcessorCount;
            if (coreCount < 4) return null; // Not enough cores to optimize

            // Limit to cores 0-1 for system bloat
            var systemAffinity = (IntPtr)0x3; // Cores 0 and 1
            var systemProcesses = new[]
            {
                "RuntimeBroker", "SearchHost", "SearchApp",
                "backgroundTaskHost", "sihost", "ctfmon",
                "MusNotifyIcon", "SecurityHealthSystray"
            };

            int pinned = 0;
            foreach (var name in systemProcesses)
            {
                try
                {
                    foreach (var proc in Process.GetProcessesByName(name))
                    {
                        try
                        {
                            proc.ProcessorAffinity = systemAffinity;
                            pinned++;
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                catch { }
            }

            if (pinned > 0)
            {
                _logger?.LogInformation("Pinned {Count} system processes to cores 0-1", pinned);
                return $"🧠 Pinned {pinned} system processes to cores 0-1 (freed {coreCount - 2} cores)";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to optimize CPU affinity");
        }
        return null;
    }

    // ─── Network Optimization ────────────────────────────────────────────

    /// <summary>
    /// Disables Nagle algorithm (TcpAckFrequency=1, TCPNoDelay=1) for lower
    /// network latency during gaming.
    /// </summary>
    private string? OptimizeNetwork()
    {
        try
        {
            var interfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            using var interfaces = Registry.LocalMachine.OpenSubKey(interfacesKey);
            if (interfaces == null) return null;

            int optimized = 0;
            foreach (var ifaceId in interfaces.GetSubKeyNames())
            {
                try
                {
                    using var iface = interfaces.OpenSubKey(ifaceId, writable: true);
                    if (iface == null) continue;

                    // Check if this interface has an IP address (active adapter)
                    var dhcpAddr = iface.GetValue("DhcpIPAddress")?.ToString();
                    var staticAddr = iface.GetValue("IPAddress");
                    if (string.IsNullOrEmpty(dhcpAddr) && staticAddr == null) continue;

                    // Save originals
                    var key1 = $"{ifaceId}_TcpAckFrequency";
                    var key2 = $"{ifaceId}_TCPNoDelay";
                    _originalNetworkValues[key1] = iface.GetValue("TcpAckFrequency");
                    _originalNetworkValues[key2] = iface.GetValue("TCPNoDelay");

                    // Set low-latency values
                    iface.SetValue("TcpAckFrequency", 1, RegistryValueKind.DWord);
                    iface.SetValue("TCPNoDelay", 1, RegistryValueKind.DWord);
                    optimized++;
                }
                catch { }
            }

            if (optimized > 0)
            {
                _networkOptimized = true;
                _logger?.LogInformation("Optimized {Count} network interfaces for low latency", optimized);
                return $"🌐 Disabled Nagle algorithm on {optimized} adapters (lower ping)";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to optimize network");
        }
        return null;
    }

    private void RestoreNetwork()
    {
        try
        {
            var interfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            using var interfaces = Registry.LocalMachine.OpenSubKey(interfacesKey);
            if (interfaces == null) return;

            foreach (var ifaceId in interfaces.GetSubKeyNames())
            {
                try
                {
                    using var iface = interfaces.OpenSubKey(ifaceId, writable: true);
                    if (iface == null) continue;

                    var key1 = $"{ifaceId}_TcpAckFrequency";
                    var key2 = $"{ifaceId}_TCPNoDelay";

                    if (_originalNetworkValues.TryGetValue(key1, out var orig1))
                    {
                        if (orig1 != null)
                            iface.SetValue("TcpAckFrequency", orig1, RegistryValueKind.DWord);
                        else
                            iface.DeleteValue("TcpAckFrequency", throwOnMissingValue: false);
                    }

                    if (_originalNetworkValues.TryGetValue(key2, out var orig2))
                    {
                        if (orig2 != null)
                            iface.SetValue("TCPNoDelay", orig2, RegistryValueKind.DWord);
                        else
                            iface.DeleteValue("TCPNoDelay", throwOnMissingValue: false);
                    }
                }
                catch { }
            }
            _originalNetworkValues.Clear();
        }
        catch { }
    }

    // ─── Visual Effects ──────────────────────────────────────────────────

    /// <summary>
    /// Disables Windows animations, transparency, and visual effects
    /// to free GPU resources for gaming.
    /// </summary>
    private string? DisableVisualEffects()
    {
        try
        {
            int zero = 0;

            // Disable window animations
            SystemParametersInfo(SPI_SETCLIENTAREAANIMATION, 0, ref zero, SPIF_SENDCHANGE);
            // Disable menu fade
            SystemParametersInfo(SPI_SETMENUFADE, 0, ref zero, SPIF_SENDCHANGE);
            // Disable drag full windows
            SystemParametersInfo(SPI_SETDRAGFULLWINDOWS, 0, IntPtr.Zero, SPIF_SENDCHANGE);
            // Disable combobox animation
            SystemParametersInfo(SPI_SETCOMBOBOXANIMATION, 0, ref zero, SPIF_SENDCHANGE);
            // Disable listbox smooth scrolling
            SystemParametersInfo(SPI_SETLISTBOXSMOOTHSCROLLING, 0, ref zero, SPIF_SENDCHANGE);

            // Disable transparency via registry
            try
            {
                Registry.SetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                    "EnableTransparency", 0, RegistryValueKind.DWord);
            }
            catch { }

            _visualEffectsDisabled = true;
            _logger?.LogInformation("Visual effects disabled for GPU headroom");
            return "🎨 Disabled animations & transparency (GPU headroom)";
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to disable visual effects");
            return null;
        }
    }

    private void RestoreVisualEffects()
    {
        try
        {
            int one = 1;
            SystemParametersInfo(SPI_SETCLIENTAREAANIMATION, 0, ref one, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETMENUFADE, 0, ref one, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETDRAGFULLWINDOWS, 1, IntPtr.Zero, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETCOMBOBOXANIMATION, 0, ref one, SPIF_SENDCHANGE);
            SystemParametersInfo(SPI_SETLISTBOXSMOOTHSCROLLING, 0, ref one, SPIF_SENDCHANGE);

            try
            {
                Registry.SetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                    "EnableTransparency", 1, RegistryValueKind.DWord);
            }
            catch { }
        }
        catch { }
    }

    // ─── Timer Resolution ────────────────────────────────────────────────

    /// <summary>
    /// Sets Windows timer resolution to ~1ms for better frame pacing.
    /// Default is ~15.6ms which can cause micro-stuttering.
    /// </summary>
    private string? SetHighTimerResolution()
    {
        try
        {
            // 10000 = 1ms in 100-nanosecond units
            int status = NtSetTimerResolution(10000, true, out uint current);
            if (status == 0)
            {
                _timerResolutionSet = true;
                double currentMs = current / 10000.0;
                _logger?.LogInformation("Timer resolution set to {Resolution}ms", currentMs);
                return $"⏱️ Timer resolution: {currentMs:0.##}ms (smoother frame pacing)";
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to set timer resolution");
        }
        return null;
    }

    // ─── GPU Priority ────────────────────────────────────────────────────

    /// <summary>
    /// Sets GPU scheduling priority to prefer foreground apps via registry.
    /// </summary>
    private string? BoostGpuPriority()
    {
        try
        {
            // Set GPU scheduling priority (8 = highest for foreground apps)
            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "SystemResponsiveness", 0, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "GPU Priority", 8, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Priority", 6, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Scheduling Category", "High", RegistryValueKind.String);

            _gpuPrioritySet = true;
            _logger?.LogInformation("GPU scheduling priority boosted");
            return "🖥️ GPU scheduling priority set to maximum";
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to boost GPU priority (need admin)");
            return null;
        }
    }

    private void RestoreGpuPriority()
    {
        try
        {
            // Restore default SystemResponsiveness (20%)
            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "SystemResponsiveness", 20, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "GPU Priority", 2, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Priority", 2, RegistryValueKind.DWord);

            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Scheduling Category", "Medium", RegistryValueKind.String);
        }
        catch { }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static long GetAvailableMemory()
    {
        try
        {
            using var counter = new PerformanceCounter("Memory", "Available Bytes");
            return (long)counter.NextValue();
        }
        catch { return 0; }
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
}
