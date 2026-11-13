// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Full-Screen Game Guard
// Proprietary implementation by DelgadoLogic.Tech
// Multi-signal sensor array & high-speed watchdog guaranteeing <500ms I/O suspension
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Native;

namespace LogicFlow.Guardian.Worker;

/// <summary>
/// High-speed gaming and full-screen workload watchdog.
/// Monitors shell notification states, window geometry vs. active monitor resolution,
/// and GPU 3D engine utilization counters at 100-150 ms cadence.
/// Automatically resets an atomic ManualResetEventSlim pause signal to guarantee
/// background storage I/O suspension within &lt;500 ms (targeting &lt;250 ms).
/// </summary>
public sealed class FullScreenGameGuard : IDisposable
{
    private static readonly ConcurrentDictionary<int, byte> s_globalExcludedPids = new(
        new[] { new KeyValuePair<int, byte>(Environment.ProcessId, 0) });

    private readonly ConcurrentDictionary<int, byte> _instanceExcludedPids = new(
        new[] { new KeyValuePair<int, byte>(Environment.ProcessId, 0) });

    private readonly ManualResetEventSlim _pauseSignal = new(true); // Signaled (unpaused) by default
    private readonly object _stateLock = new();
    private CancellationTokenSource? _watchdogCts;
    private Task? _watchdogTask;
    private volatile bool _isGameActive;
    private volatile bool _isDisposed;

    // Performance counter cache for GPU 3D utilization (stores instance name + counter for dynamic PID filtering)
    private List<(string InstanceName, PerformanceCounter Counter)>? _gpu3dCounters;
    private bool _gpuCountersChecked;
    private DateTime _lastGpuSampleTime = DateTime.MinValue;
    private double _lastGpuUtilization;

    /// <summary>
    /// Global event raised whenever any FullScreenGameGuard instance detects a real game or full-screen workload.
    /// Subscribed by GemmaAiEngine to immediately unload the local sidecar process and free 100% of VRAM/RAM.
    /// </summary>
    public static event Action? GlobalGameDetected;

    #region Excluded Process ID Management (Self-Sabotage Prevention)

    /// <summary>
    /// Registers a process ID (such as the local llama-server.exe sidecar) globally and on this instance
    /// so its GPU 3D engine counters are excluded from Sensor 3 game detection.
    /// </summary>
    public void RegisterExcludedProcessId(int pid)
    {
        if (pid <= 0) return;
        _instanceExcludedPids[pid] = 0;
        s_globalExcludedPids[pid] = 0;
    }

    /// <summary>
    /// Unregisters a previously excluded process ID. Never removes the current LogicFlow process ID.
    /// </summary>
    public void UnregisterExcludedProcessId(int pid)
    {
        if (pid <= 0 || pid == Environment.ProcessId) return;
        _instanceExcludedPids.TryRemove(pid, out _);
        s_globalExcludedPids.TryRemove(pid, out _);
    }

    /// <summary>
    /// Registers a process ID globally across all FullScreenGameGuard instances.
    /// </summary>
    public static void RegisterGlobalExcludedProcessId(int pid)
    {
        if (pid <= 0) return;
        s_globalExcludedPids[pid] = 0;
    }

    /// <summary>
    /// Unregisters a process ID globally across all FullScreenGameGuard instances.
    /// </summary>
    public static void UnregisterGlobalExcludedProcessId(int pid)
    {
        if (pid <= 0 || pid == Environment.ProcessId) return;
        s_globalExcludedPids.TryRemove(pid, out _);
    }

    /// <summary>
    /// Returns the snapshot of currently excluded PIDs (always includes Environment.ProcessId).
    /// </summary>
    public IReadOnlyCollection<int> GetExcludedProcessIds()
    {
        var set = new HashSet<int>(s_globalExcludedPids.Keys);
        foreach (var k in _instanceExcludedPids.Keys)
            set.Add(k);
        set.Add(Environment.ProcessId);
        return set;
    }

    /// <summary>
    /// Returns true if a Windows "GPU Engine" counter instance name belongs to the current LogicFlow process
    /// or any registered excluded sidecar process ID (format: "pid_1234_luid_..._engtype_3D").
    /// </summary>
    public bool IsExcludedCounterInstance(string? instanceName)
    {
        if (string.IsNullOrWhiteSpace(instanceName))
            return false;

        int parsedPid = TryExtractPidFromInstanceName(instanceName);
        if (parsedPid > 0)
        {
            if (parsedPid == Environment.ProcessId ||
                _instanceExcludedPids.ContainsKey(parsedPid) ||
                s_globalExcludedPids.ContainsKey(parsedPid))
            {
                return true;
            }
        }

        // Fallback substring check in case of non-standard prefix formatting
        if (instanceName.Contains($"pid_{Environment.ProcessId}_", StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var pid in _instanceExcludedPids.Keys)
        {
            if (instanceName.Contains($"pid_{pid}_", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var pid in s_globalExcludedPids.Keys)
        {
            if (instanceName.Contains($"pid_{pid}_", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static int TryExtractPidFromInstanceName(string instanceName)
    {
        int idx = instanceName.IndexOf("pid_", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return -1;

        int start = idx + 4;
        int end = start;
        while (end < instanceName.Length && char.IsDigit(instanceName[end]))
        {
            end++;
        }

        if (end > start && int.TryParse(instanceName.AsSpan(start, end - start), out int pid))
        {
            return pid;
        }

        return -1;
    }

    #endregion

    #region Configuration & Test Hooks

    /// <summary>
    /// Watchdog polling interval (default: 100 ms, guaranteeing &lt;250 ms suspension latency).
    /// </summary>
    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// GPU 3D engine utilization percentage threshold to trigger suspension (default: 35.0%).
    /// </summary>
    public double GpuThresholdPercentage { get; set; } = 35.0;

    /// <summary>
    /// Number of consecutive clear polls required before unpausing the worker (hysteresis cooldown, default: 3).
    /// </summary>
    public int CooldownPollCount { get; set; } = 3;

    /// <summary>
    /// Atomic ManualResetEventSlim controlling worker thread I/O execution.
    /// Signaled (IsSet == true) when system is clear; Reset (IsSet == false) when a game or full-screen app is active.
    /// </summary>
    public ManualResetEventSlim PauseSignal => _pauseSignal;

    /// <summary>
    /// Returns true if a full-screen game, intensive 3D workload, or presentation mode is currently active.
    /// </summary>
    public bool IsGameActive => _isGameActive;

    /// <summary>
    /// Optional callback invoked immediately when a game is detected to unload local AI sidecars.
    /// </summary>
    public Action? SidecarTerminationAction { get; set; }

    /// <summary>
    /// Optional test seam: override shell notification state.
    /// </summary>
    public Func<SensorsNative.QUERY_USER_NOTIFICATION_STATE>? UserNotificationStateProvider { get; set; }

    /// <summary>
    /// Optional test seam: override foreground window full screen detection.
    /// </summary>
    public Func<bool>? FullScreenWindowProvider { get; set; }

    /// <summary>
    /// Optional test seam: override GPU 3D engine utilization percentage.
    /// </summary>
    public Func<double>? GpuUtilizationProvider { get; set; }

    /// <summary>
    /// Optional test seam: provide raw GPU counter instances (InstanceName, UtilizationValue)
    /// to test excluded PID filtering deterministically without live Windows GPU counters.
    /// </summary>
    public Func<IEnumerable<(string InstanceName, double Value)>>? GpuCounterInstancesProvider { get; set; }

    #endregion

    #region Events

    /// <summary>
    /// Triggered whenever the game or full screen state changes (true = game active/paused, false = clear/resumed).
    /// </summary>
    public event EventHandler<bool>? OnGameStateChanged;

    /// <summary>
    /// Triggered immediately when a game or full-screen application is detected.
    /// </summary>
    public event EventHandler? OnGameDetected;

    /// <summary>
    /// Triggered when the game or full-screen application exits and cooldown expires.
    /// </summary>
    public event EventHandler? OnGameExited;

    #endregion

    /// <summary>
    /// Starts the high-speed watchdog background polling loop.
    /// </summary>
    public void Start()
    {
        lock (_stateLock)
        {
            if (_isDisposed) throw new ObjectDisposedException(nameof(FullScreenGameGuard));
            if (_watchdogTask != null) return; // Already running

            _watchdogCts = new CancellationTokenSource();
            var token = _watchdogCts.Token;
            var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var thread = new Thread(() =>
            {
                try
                {
                    WatchdogLoop(token);
                }
                finally
                {
                    tcs.TrySetResult();
                }
            })
            {
                IsBackground = true,
                Name = "LogicFlow.FullScreenGameGuard",
                Priority = ThreadPriority.AboveNormal
            };
            _watchdogTask = tcs.Task;
            thread.Start();
        }
    }

    /// <summary>
    /// Stops the high-speed watchdog loop and resets state.
    /// </summary>
    public void Stop()
    {
        CancellationTokenSource? cts;
        Task? task;

        lock (_stateLock)
        {
            cts = _watchdogCts;
            task = _watchdogTask;
            _watchdogCts = null;
            _watchdogTask = null;
        }

        if (cts != null)
        {
            try
            {
                cts.Cancel();
                task?.Wait(TimeSpan.FromSeconds(2));
            }
            catch (AggregateException) { }
            catch (OperationCanceledException) { }
            finally
            {
                cts.Dispose();
            }
        }

        // Restore signal on stop
        _pauseSignal.Set();
        _isGameActive = false;
    }

    /// <summary>
    /// Immediately checks all three sensor signals without waiting for the next watchdog cycle.
    /// Returns true if a game or full-screen workload is active.
    /// </summary>
    public bool CheckIsGameRunning()
    {
        bool detected =
            CheckNotificationStateSensor(out _) ||
            CheckWindowGeometrySensor(out _) ||
            CheckGpuUtilizationSensor(out _);

        if (detected && !_isGameActive)
        {
            try { SidecarTerminationAction?.Invoke(); } catch { }
            try { GlobalGameDetected?.Invoke(); } catch { }
        }

        return detected;
    }

    /// <summary>
    /// High-frequency watchdog loop executing at 100-150 ms intervals on a dedicated thread.
    /// </summary>
    private void WatchdogLoop(CancellationToken ct)
    {
        int clearStreak = 0;

        if (ct.WaitHandle.WaitOne(PollingInterval))
            return;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                bool gameDetected = CheckIsGameRunning();

                if (gameDetected)
                {
                    clearStreak = 0;
                    if (!_isGameActive)
                    {
                        // Transition to Active Game / Suspended state
                        _isGameActive = true;
                        _pauseSignal.Reset(); // Atomic pause signal to worker threads

                        // Immediately terminate/unload local AI sidecar so 100% of VRAM & RAM is returned to the OS
                        try { SidecarTerminationAction?.Invoke(); } catch { }
                        try { GlobalGameDetected?.Invoke(); } catch { }

                        OnGameDetected?.Invoke(this, EventArgs.Empty);
                        OnGameStateChanged?.Invoke(this, true);
                    }
                }
                else
                {
                    if (_isGameActive)
                    {
                        clearStreak++;
                        if (clearStreak >= CooldownPollCount)
                        {
                            // Transition to Clear / Resumed state
                            _isGameActive = false;
                            _pauseSignal.Set(); // Atomic resume signal

                            OnGameExited?.Invoke(this, EventArgs.Empty);
                            OnGameStateChanged?.Invoke(this, false);
                        }
                    }
                    else
                    {
                        clearStreak = 0;
                        if (!_pauseSignal.IsSet)
                        {
                            _pauseSignal.Set();
                        }
                    }
                }

                if (ct.WaitHandle.WaitOne(PollingInterval))
                    break;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Watchdog must never terminate unexpectedly
                try
                {
                    if (ct.WaitHandle.WaitOne(PollingInterval))
                        break;
                }
                catch
                {
                    break;
                }
            }
        }
    }

    #region Individual Sensor Evaluators

    /// <summary>
    /// Evaluates Sensor 1: Shell Notification State.
    /// </summary>
    public bool CheckNotificationStateSensor(out string reason)
    {
        reason = string.Empty;

        SensorsNative.QUERY_USER_NOTIFICATION_STATE state;
        if (UserNotificationStateProvider != null)
        {
            state = UserNotificationStateProvider();
        }
        else if (!SensorsNative.TryQueryUserNotificationState(out state))
        {
            return false;
        }

        if (state == SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_RUNNING_D3D_FULL_SCREEN)
        {
            reason = $"D3D Full-Screen Game Detected ({state})";
            return true;
        }

        if (state == SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_BUSY ||
            state == SensorsNative.QUERY_USER_NOTIFICATION_STATE.QUNS_PRESENTATION_MODE)
        {
            reason = $"Shell Busy or Presentation Mode Active ({state})";
            return true;
        }

        return false;
    }

    /// <summary>
    /// Evaluates Sensor 2: Window Geometry vs Monitor Resolution.
    /// </summary>
    public bool CheckWindowGeometrySensor(out string reason)
    {
        reason = string.Empty;

        if (FullScreenWindowProvider != null)
        {
            if (FullScreenWindowProvider())
            {
                reason = "Simulated Foreground Full-Screen Window Detected";
                return true;
            }
            return false;
        }

        if (SensorsNative.IsForegroundWindowFullScreen(out var winRect, out var monRect))
        {
            reason = $"Foreground Window covers monitor ({winRect.Width}x{winRect.Height} on {monRect.Width}x{monRect.Height})";
            return true;
        }

        return false;
    }

    /// <summary>
    /// Evaluates Sensor 3: GPU 3D Utilization Spike (excluding LogicFlow and registered AI sidecar PIDs).
    /// </summary>
    public bool CheckGpuUtilizationSensor(out string reason)
    {
        reason = string.Empty;

        double gpuUsage;
        if (GpuUtilizationProvider != null)
        {
            gpuUsage = GpuUtilizationProvider();
        }
        else if (GpuCounterInstancesProvider != null)
        {
            gpuUsage = 0.0;
            foreach (var (instanceName, val) in GpuCounterInstancesProvider())
            {
                if (string.IsNullOrWhiteSpace(instanceName)) continue;
                if (instanceName.IndexOf("engtype_3D", StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (IsExcludedCounterInstance(instanceName)) continue;
                gpuUsage += val;
            }
        }
        else
        {
            gpuUsage = ReadGpu3DUtilization();
        }

        if (gpuUsage >= GpuThresholdPercentage)
        {
            reason = $"GPU 3D Engine Load Spike ({gpuUsage:F1}% >= {GpuThresholdPercentage:F1}%)";
            return true;
        }

        return false;
    }

    private double ReadGpu3DUtilization()
    {
        // Cache GPU readings for at least 200 ms to avoid performance counter overhead
        if ((DateTime.UtcNow - _lastGpuSampleTime).TotalMilliseconds < 200)
        {
            return _lastGpuUtilization;
        }

        _lastGpuSampleTime = DateTime.UtcNow;

        try
        {
            if (!_gpuCountersChecked)
            {
                _gpuCountersChecked = true;
                InitializeGpuCountersSafe();
            }

            if (_gpu3dCounters == null || _gpu3dCounters.Count == 0)
            {
                _lastGpuUtilization = 0.0;
                return 0.0;
            }

            double total = 0.0;
            foreach (var (instanceName, counter) in _gpu3dCounters)
            {
                if (IsExcludedCounterInstance(instanceName))
                    continue;

                try
                {
                    total += counter.NextValue();
                }
                catch
                {
                    // Ignore counter instance read errors
                }
            }

            _lastGpuUtilization = total;
            return total;
        }
        catch
        {
            _lastGpuUtilization = 0.0;
            return 0.0;
        }
    }

    private void InitializeGpuCountersSafe()
    {
        try
        {
            if (!PerformanceCounterCategory.Exists("GPU Engine"))
            {
                _gpu3dCounters = null;
                return;
            }

            var category = new PerformanceCounterCategory("GPU Engine");
            var instanceNames = category.GetInstanceNames();

            var list = new List<(string InstanceName, PerformanceCounter Counter)>();
            foreach (var name in instanceNames)
            {
                if (name.IndexOf("engtype_3D", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (IsExcludedCounterInstance(name))
                        continue;

                    try
                    {
                        var counter = new PerformanceCounter("GPU Engine", "Utilization Percentage", name, readOnly: true);
                        counter.NextValue(); // Prime first sample
                        list.Add((name, counter));
                    }
                    catch
                    {
                        // Ignore individual counter init errors
                    }
                }
            }

            _gpu3dCounters = list.Count > 0 ? list : null;
        }
        catch
        {
            _gpu3dCounters = null;
        }
    }

    #endregion

    public void Dispose()
    {
        lock (_stateLock)
        {
            if (_isDisposed) return;
            _isDisposed = true;
        }

        Stop();

        if (_gpu3dCounters != null)
        {
            foreach (var (_, counter) in _gpu3dCounters)
            {
                try { counter.Dispose(); } catch { }
            }
            _gpu3dCounters = null;
        }

        _pauseSignal.Dispose();
    }
}
