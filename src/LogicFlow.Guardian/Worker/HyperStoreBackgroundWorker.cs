// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Autonomous HyperStore Background Worker
// Proprietary implementation by DelgadoLogic.Tech
// Coordinates Smart Idle Sensor, Full-Screen Game Guard, and Volume-Aware Deduplication
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Guardian.Deduplication;
using LogicFlow.Native;

namespace LogicFlow.Guardian.Worker;

/// <summary>
/// Autonomous background storage worker orchestrating Volume-Aware host deduplication passes.
/// Governed by Smart Idle detection (>5 min idle, AC power connected) and Full-Screen Game Guard
/// (<500 ms suspension SLA). Configurable for ContinuousLowPriority, ScheduledWindow, or ManualOnly.
/// </summary>
public sealed class HyperStoreBackgroundWorker : IDisposable
{
    private readonly object _stateLock = new();
    private readonly SmartIdleSensor _idleSensor;
    private readonly FullScreenGameGuard _gameGuard;
    private readonly VolumeAwareDeduplicator _deduplicator;

    private WorkerSettings _settings;
    private volatile WorkerState _state = WorkerState.Stopped;
    private volatile bool _isPausedByUser;
    private volatile bool _isDisposed;

    private CancellationTokenSource? _workerCts;
    private Task? _workerLoopTask;

    /// <summary>
    /// Current state of the background storage worker.
    /// </summary>
    public WorkerState State
    {
        get => _state;
        private set
        {
            if (_state != value)
            {
                WorkerState previous;
                lock (_stateLock)
                {
                    previous = _state;
                    _state = value;
                }
                OnStateChanged?.Invoke(this, value);
            }
        }
    }

    /// <summary>
    /// Worker configuration settings.
    /// </summary>
    public WorkerSettings Settings
    {
        get => _settings;
        set => _settings = value ?? new WorkerSettings();
    }

    /// <summary>
    /// Smart Idle and power sensor instance.
    /// </summary>
    public SmartIdleSensor IdleSensor => _idleSensor;

    /// <summary>
    /// Full-screen gaming and intensive 3D workload watchdog.
    /// </summary>
    public FullScreenGameGuard GameGuard => _gameGuard;

    /// <summary>
    /// Underlying volume-aware host deduplication engine.
    /// </summary>
    public VolumeAwareDeduplicator Deduplicator => _deduplicator;

    /// <summary>
    /// Fired when an optimization event occurs (antivirus-style real-time telemetry).
    /// </summary>
    public event EventHandler<OptimizationEvent>? OnOptimizationEvent;

    /// <summary>
    /// Fired whenever the worker state transitions.
    /// </summary>
    public event EventHandler<WorkerState>? OnStateChanged;

    /// <summary>
    /// Initializes a new HyperStore background worker with default settings and production sensors.
    /// </summary>
    public HyperStoreBackgroundWorker() : this(new WorkerSettings(), null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new HyperStore background worker with specified settings.
    /// </summary>
    public HyperStoreBackgroundWorker(WorkerSettings settings) : this(settings, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new HyperStore background worker with injectable dependencies for testing.
    /// </summary>
    public HyperStoreBackgroundWorker(
        WorkerSettings? settings = null,
        SmartIdleSensor? idleSensor = null,
        FullScreenGameGuard? gameGuard = null,
        VolumeAwareDeduplicator? deduplicator = null)
    {
        _settings = settings ?? new WorkerSettings();
        _idleSensor = idleSensor ?? new SmartIdleSensor
        {
            IdleThreshold = _settings.IdleThreshold,
            RequireAcPower = _settings.RequireAcPower
        };
        _gameGuard = gameGuard ?? new FullScreenGameGuard
        {
            GpuThresholdPercentage = _settings.GpuUtilizationThreshold
        };
        _deduplicator = deduplicator ?? VolumeAwareDeduplicator.Instance;

        // Wire game guard events to handle fast state transition
        _gameGuard.OnGameStateChanged += (s, isGameActive) =>
        {
            if (_state != WorkerState.Stopped && !_isPausedByUser)
            {
                if (isGameActive)
                {
                    State = WorkerState.SuspendedByGameGuard;
                }
                else if (State == WorkerState.SuspendedByGameGuard)
                {
                    State = WorkerState.WaitingForIdle;
                }
            }
        };

        // Wire power state changes
        _idleSensor.PowerStateChanged += (s, isAcConnected) =>
        {
            if (_state != WorkerState.Stopped && !_isPausedByUser && _settings.RequireAcPower)
            {
                if (!isAcConnected)
                {
                    State = WorkerState.SuspendedByBattery;
                }
                else if (State == WorkerState.SuspendedByBattery)
                {
                    State = WorkerState.WaitingForIdle;
                }
            }
        };
    }

    /// <summary>
    /// Starts the autonomous background storage worker loop and initiates sensor monitoring.
    /// </summary>
    public void Start()
    {
        lock (_stateLock)
        {
            if (_isDisposed) throw new ObjectDisposedException(nameof(HyperStoreBackgroundWorker));
            if (_workerLoopTask != null) return; // Already running

            _isPausedByUser = false;
            _idleSensor.IdleThreshold = _settings.IdleThreshold;
            _idleSensor.RequireAcPower = _settings.RequireAcPower;
            _gameGuard.GpuThresholdPercentage = _settings.GpuUtilizationThreshold;

            _gameGuard.Start();

            _workerCts = new CancellationTokenSource();
            State = WorkerState.WaitingForIdle;
            _workerLoopTask = Task.Run(() => WorkerLoopAsync(_workerCts.Token));
        }
    }

    /// <summary>
    /// Stops the background storage worker loop and restores priority.
    /// </summary>
    public void Stop()
    {
        CancellationTokenSource? cts;
        Task? task;

        lock (_stateLock)
        {
            cts = _workerCts;
            task = _workerLoopTask;
            _workerCts = null;
            _workerLoopTask = null;
        }

        if (cts != null)
        {
            try
            {
                cts.Cancel();
                task?.Wait(TimeSpan.FromSeconds(3));
            }
            catch (AggregateException) { }
            catch (OperationCanceledException) { }
            finally
            {
                cts.Dispose();
            }
        }

        _gameGuard.Stop();

        if (_settings.EnableBackgroundPriority)
        {
            SensorsNative.TrySetBackgroundPriority(false);
        }

        State = WorkerState.Stopped;
    }

    /// <summary>
    /// Explicitly pauses the worker by user request.
    /// </summary>
    public void Pause()
    {
        lock (_stateLock)
        {
            if (_state == WorkerState.Stopped) return;
            _isPausedByUser = true;
            State = WorkerState.PausedByUser;
        }
    }

    /// <summary>
    /// Resumes the worker after a user-initiated pause.
    /// </summary>
    public void Resume()
    {
        lock (_stateLock)
        {
            if (_state != WorkerState.PausedByUser) return;
            _isPausedByUser = false;
            State = WorkerState.WaitingForIdle;
        }
    }

    /// <summary>
    /// Triggers an immediate, synchronous-style manual deduplication sweep across target directories.
    /// </summary>
    public void TriggerManualPass()
    {
        TriggerManualPassAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Triggers an immediate manual deduplication pass asynchronously.
    /// Bypasses idle and scheduled window checks, but respects Game Guard and Battery safety guards.
    /// </summary>
    public async Task<DedupResult> TriggerManualPassAsync(CancellationToken ct = default)
    {
        // 1. Safety verification
        if (_gameGuard.IsGameActive || _gameGuard.CheckIsGameRunning())
        {
            State = WorkerState.SuspendedByGameGuard;
            throw new InvalidOperationException("Cannot execute storage optimization pass while a full-screen game or high GPU workload is active.");
        }

        if (_settings.RequireAcPower && _idleSensor.IsOnBattery())
        {
            State = WorkerState.SuspendedByBattery;
            throw new InvalidOperationException("Cannot execute storage optimization pass while operating on battery power.");
        }

        WorkerState previousState = State;
        State = WorkerState.Optimizing;

        var combinedResult = new DedupResult();
        try
        {
            combinedResult = await ExecuteOptimizationPassAsync(ct).ConfigureAwait(false);
            return combinedResult;
        }
        finally
        {
            if (_state == WorkerState.Optimizing)
            {
                State = previousState == WorkerState.Stopped ? WorkerState.Stopped : WorkerState.WaitingForIdle;
            }
        }
    }

    /// <summary>
    /// Publishes an optimization event to all registered telemetry subscribers.
    /// </summary>
    public void PublishOptimizationEvent(OptimizationEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        OnOptimizationEvent?.Invoke(this, evt);
    }

    /// <summary>
    /// Main autonomous background worker loop.
    /// </summary>
    private async Task WorkerLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                // 1. Handle user pause
                if (_isPausedByUser)
                {
                    if (State != WorkerState.PausedByUser) State = WorkerState.PausedByUser;
                    await Task.Delay(500, ct).ConfigureAwait(false);
                    continue;
                }

                // 2. Handle Game Guard pause signal (<500 ms SLA)
                if (_gameGuard.IsGameActive)
                {
                    if (State != WorkerState.SuspendedByGameGuard) State = WorkerState.SuspendedByGameGuard;
                    _gameGuard.PauseSignal.Wait(500, ct);
                    continue;
                }

                // 3. Handle Battery pause
                if (_settings.RequireAcPower && _idleSensor.IsOnBattery())
                {
                    if (State != WorkerState.SuspendedByBattery) State = WorkerState.SuspendedByBattery;
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                    continue;
                }

                // 4. Handle Operational Modes
                switch (_settings.Mode)
                {
                    case WorkerExecutionMode.ManualOnly:
                        // In ManualOnly, do not auto-trigger
                        if (State != WorkerState.WaitingForIdle) State = WorkerState.WaitingForIdle;
                        await Task.Delay(1000, ct).ConfigureAwait(false);
                        break;

                    case WorkerExecutionMode.ScheduledWindow:
                        bool inWindow = _settings.IsInScheduledWindow(DateTime.Now.TimeOfDay);
                        bool isIdleSched = _idleSensor.IsIdle();

                        if (!inWindow || !isIdleSched)
                        {
                            if (State != WorkerState.WaitingForIdle) State = WorkerState.WaitingForIdle;
                            await Task.Delay(1000, ct).ConfigureAwait(false);
                        }
                        else
                        {
                            await RunAutonomousOptimizationCycleAsync(ct).ConfigureAwait(false);
                        }
                        break;

                    case WorkerExecutionMode.ContinuousLowPriority:
                    default:
                        bool isIdle = _idleSensor.IsIdle();
                        if (!isIdle)
                        {
                            if (State != WorkerState.WaitingForIdle) State = WorkerState.WaitingForIdle;
                            await Task.Delay(1000, ct).ConfigureAwait(false);
                        }
                        else
                        {
                            await RunAutonomousOptimizationCycleAsync(ct).ConfigureAwait(false);
                        }
                        break;
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Protect worker loop from unhandled exceptions
                try
                {
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Executes an autonomous optimization cycle with low process priority and game guard checks.
    /// </summary>
    private async Task RunAutonomousOptimizationCycleAsync(CancellationToken ct)
    {
        State = WorkerState.Optimizing;

        if (_settings.EnableBackgroundPriority)
        {
            SensorsNative.TrySetBackgroundPriority(true);
        }

        try
        {
            await ExecuteOptimizationPassAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            if (_settings.EnableBackgroundPriority)
            {
                SensorsNative.TrySetBackgroundPriority(false);
            }

            if (State == WorkerState.Optimizing)
            {
                State = WorkerState.WaitingForIdle;
            }
        }

        // Sleep for configured sweep interval between complete passes
        await Task.Delay(_settings.SweepInterval, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Executes deduplication passes across all configured target directories, publishing telemetry events.
    /// </summary>
    private async Task<DedupResult> ExecuteOptimizationPassAsync(CancellationToken ct)
    {
        var aggregateResult = new DedupResult();
        var targetPaths = _settings.TargetDirectories.Where(Directory.Exists).ToList();

        if (targetPaths.Count == 0)
        {
            return aggregateResult;
        }

        foreach (var dir in targetPaths)
        {
            ct.ThrowIfCancellationRequested();

            // Wait for Game Guard if game active
            if (!_gameGuard.PauseSignal.Wait(0))
            {
                State = WorkerState.SuspendedByGameGuard;
                _gameGuard.PauseSignal.Wait(ct);
                State = WorkerState.Optimizing;
            }

            // Check battery
            if (_settings.RequireAcPower && _idleSensor.IsOnBattery())
            {
                State = WorkerState.SuspendedByBattery;
                break;
            }

            try
            {
                var dirResult = await _deduplicator.DeduplicateDirectoryAsync(
                    dir,
                    _settings.DedupOptions,
                    null,
                    ct).ConfigureAwait(false);

                // Aggregate counts
                aggregateResult.TotalFilesScanned += dirResult.TotalFilesScanned;
                aggregateResult.DuplicateClustersFound += dirResult.DuplicateClustersFound;
                aggregateResult.DuplicatesConsolidated += dirResult.DuplicatesConsolidated;
                aggregateResult.MutableFilesPreserved += dirResult.MutableFilesPreserved;
                aggregateResult.CrossVolumeFilesHandled += dirResult.CrossVolumeFilesHandled;
                aggregateResult.TotalBytesReclaimed += dirResult.TotalBytesReclaimed;
                aggregateResult.Items.AddRange(dirResult.Items);

                // Fire telemetry events for each successfully consolidated item
                foreach (var item in dirResult.Items.Where(i => i.Success && i.BytesReclaimed > 0))
                {
                    PublishOptimizationEvent(new OptimizationEvent(
                        item.TargetPath,
                        item.Method.ToString(),
                        item.BytesReclaimed,
                        null,
                        DateTime.UtcNow));
                }

                // If clusters were consolidated, publish a directory summary event
                if (dirResult.DuplicatesConsolidated > 0 && dirResult.TotalBytesReclaimed > 0)
                {
                    PublishOptimizationEvent(new OptimizationEvent(
                        dir,
                        "DirectorySweepCompleted",
                        dirResult.TotalBytesReclaimed,
                        $"[{DateTime.Now:HH:mm:ss}] Consolidated {dirResult.DuplicatesConsolidated} duplicate files in {Path.GetFileName(dir)} — Saved {FormatBytes(dirResult.TotalBytesReclaimed)}",
                        DateTime.UtcNow));
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                aggregateResult.Errors.Add($"Error optimizing directory '{dir}': {ex.Message}");
            }
        }

        return aggregateResult;
    }

    private static string FormatBytes(long bytes)
    {
        return bytes >= 1024L * 1024 * 1024
            ? $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB"
            : bytes >= 1024L * 1024
                ? $"{bytes / (1024.0 * 1024.0):F1} MB"
                : bytes >= 1024L
                    ? $"{bytes / 1024.0:F1} KB"
                    : $"{bytes} B";
    }

    public void Dispose()
    {
        lock (_stateLock)
        {
            if (_isDisposed) return;
            _isDisposed = true;
        }

        Stop();
        _gameGuard.Dispose();
    }
}
