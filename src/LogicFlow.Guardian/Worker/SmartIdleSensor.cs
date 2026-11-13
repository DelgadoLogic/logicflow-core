// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Smart Idle & Power Sensor
// Proprietary implementation by DelgadoLogic.Tech
// Measures system idle time via GetLastInputInfo and monitors AC power status
// ─────────────────────────────────────────────────────────────────────────────

using System;
using LogicFlow.Native;

namespace LogicFlow.Guardian.Worker;

/// <summary>
/// Result of evaluating smart idle and power preconditions.
/// </summary>
public sealed record SmartIdleEvaluation(
    bool CanOperate,
    TimeSpan IdleDuration,
    bool IsIdle,
    bool IsAcConnected,
    string Reason
);

/// <summary>
/// Autonomous environmental sensor measuring system user inactivity duration and AC power status.
/// Governs background storage optimization passes to ensure zero disturbance to active users.
/// </summary>
public sealed class SmartIdleSensor
{
    private TimeSpan _idleThreshold = TimeSpan.FromMinutes(5); // 300,000 ms
    private bool _requireAcPower = true;

    /// <summary>
    /// Inactivity threshold required before the system is considered idle (default: 5 minutes = 300,000 ms).
    /// </summary>
    public TimeSpan IdleThreshold
    {
        get => _idleThreshold;
        set => _idleThreshold = value < TimeSpan.Zero ? TimeSpan.Zero : value;
    }

    /// <summary>
    /// If true, requires AC line power to operate and inhibits operation when running on battery (default: true).
    /// </summary>
    public bool RequireAcPower
    {
        get => _requireAcPower;
        set => _requireAcPower = value;
    }

    /// <summary>
    /// Optional delegate to provide idle duration for testing and simulation.
    /// </summary>
    public Func<TimeSpan>? IdleDurationProvider { get; set; }

    /// <summary>
    /// Optional delegate to provide AC power connection status for testing and simulation.
    /// </summary>
    public Func<bool>? AcPowerConnectedProvider { get; set; }

    /// <summary>
    /// Event triggered when the idle state transitions between idle and active.
    /// </summary>
    public event EventHandler<bool>? IdleStateChanged;

    /// <summary>
    /// Event triggered when the power status transitions between AC and Battery.
    /// </summary>
    public event EventHandler<bool>? PowerStateChanged;

    private bool? _lastReportedIdle;
    private bool? _lastReportedAc;

    /// <summary>
    /// Gets the current duration of user inactivity since the last keyboard or mouse input event.
    /// </summary>
    public TimeSpan GetIdleDuration()
    {
        if (IdleDurationProvider != null)
        {
            return IdleDurationProvider();
        }

        if (SensorsNative.TryGetSystemIdleDuration(out var duration))
        {
            return duration;
        }

        return TimeSpan.Zero;
    }

    /// <summary>
    /// Checks whether the user inactivity duration equals or exceeds the configured IdleThreshold.
    /// </summary>
    public bool IsIdle()
    {
        return GetIdleDuration() >= IdleThreshold;
    }

    /// <summary>
    /// Checks whether the system is connected to AC wall power.
    /// </summary>
    public bool IsAcPowerConnected()
    {
        if (AcPowerConnectedProvider != null)
        {
            return AcPowerConnectedProvider();
        }

        return SensorsNative.IsAcPowerConnected();
    }

    /// <summary>
    /// Checks whether the system is operating on battery power.
    /// </summary>
    public bool IsOnBattery()
    {
        return !IsAcPowerConnected();
    }

    /// <summary>
    /// Evaluates whether environmental preconditions permit background storage optimization:
    /// - User inactivity must meet or exceed IdleThreshold (>5 min by default).
    /// - AC wall power must be connected if RequireAcPower is true.
    /// </summary>
    public bool CanOperate()
    {
        bool isIdle = IsIdle();
        bool isAc = IsAcPowerConnected();

        NotifyStateChangesIfChanged(isIdle, isAc);

        if (!isIdle) return false;
        if (RequireAcPower && !isAc) return false;

        return true;
    }

    /// <summary>
    /// Generates a comprehensive evaluation report of the idle and power state.
    /// </summary>
    public SmartIdleEvaluation Evaluate()
    {
        TimeSpan idleDuration = GetIdleDuration();
        bool isIdle = idleDuration >= IdleThreshold;
        bool isAc = IsAcPowerConnected();

        NotifyStateChangesIfChanged(isIdle, isAc);

        if (!isIdle)
        {
            return new SmartIdleEvaluation(
                false,
                idleDuration,
                false,
                isAc,
                $"System is active. Idle time {idleDuration.TotalMinutes:F1}m is below threshold {IdleThreshold.TotalMinutes:F1}m."
            );
        }

        if (RequireAcPower && !isAc)
        {
            return new SmartIdleEvaluation(
                false,
                idleDuration,
                true,
                false,
                "System is running on battery power. Background storage I/O suspended to conserve battery life."
            );
        }

        return new SmartIdleEvaluation(
            true,
            idleDuration,
            true,
            isAc,
            "Preconditions satisfied. System is idle and AC power is connected."
        );
    }

    private void NotifyStateChangesIfChanged(bool isIdle, bool isAc)
    {
        if (_lastReportedIdle != isIdle)
        {
            _lastReportedIdle = isIdle;
            IdleStateChanged?.Invoke(this, isIdle);
        }

        if (_lastReportedAc != isAc)
        {
            _lastReportedAc = isAc;
            PowerStateChanged?.Invoke(this, isAc);
        }
    }
}
