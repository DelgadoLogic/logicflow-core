#pragma warning disable CA1416
// OmniCore.Engine — Event Trigger Service
// Proprietary implementation by DelgadoLogic.Tech
// Uses WMI event subscriptions for ultra-low-resource background monitoring

using System.Management;
using Microsoft.Extensions.Logging;

namespace OmniCore.Engine;

/// <summary>
/// Manages WMI event subscriptions for real-time Windows event monitoring.
/// Designed for "Antigravity" efficiency: <15MB RSS, event-driven (no polling).
/// </summary>
public sealed class EventTriggerService : IDisposable
{
    private readonly ILogger<EventTriggerService> _logger;
    private readonly Dictionary<string, ManagementEventWatcher> _activeWatchers = new();
    private bool _disposed;

    public event EventHandler<SystemEventArgs>? OnSystemEvent;

    public EventTriggerService(ILogger<EventTriggerService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Subscribes to a WMI event class with the given polling interval.
    /// </summary>
    public void Subscribe(string eventName, string wqlQuery, TimeSpan pollInterval)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_activeWatchers.ContainsKey(eventName))
        {
            _logger.LogWarning("Event '{EventName}' already subscribed. Skipping.", eventName);
            return;
        }

        var query = new WqlEventQuery(wqlQuery) { WithinInterval = pollInterval };
        var watcher = new ManagementEventWatcher(query);

        watcher.EventArrived += (sender, args) =>
        {
            var eventArgs = new SystemEventArgs(eventName, args.NewEvent);
            _logger.LogInformation("WMI event fired: {EventName}", eventName);
            OnSystemEvent?.Invoke(this, eventArgs);
        };

        watcher.Start();
        _activeWatchers[eventName] = watcher;
        _logger.LogInformation("Subscribed to WMI event: {EventName} | Query: {Query}", eventName, wqlQuery);
    }

    /// <summary>
    /// Registers common system events for LogicFlow monitoring.
    /// </summary>
    public void RegisterDefaultEvents()
    {
        // Monitor new process creation (for startup optimization)
        Subscribe("ProcessCreated",
            "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'",
            TimeSpan.FromSeconds(5));

        // Monitor service state changes (for telemetry suppression)
        Subscribe("ServiceChanged",
            "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Service'",
            TimeSpan.FromSeconds(10));

        // Monitor USB device insertion (for Lazarus auto-detect)
        Subscribe("UsbInserted",
            "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBControllerDevice'",
            TimeSpan.FromSeconds(2));
    }

    public void Unsubscribe(string eventName)
    {
        if (_activeWatchers.TryGetValue(eventName, out var watcher))
        {
            watcher.Stop();
            watcher.Dispose();
            _activeWatchers.Remove(eventName);
            _logger.LogInformation("Unsubscribed from WMI event: {EventName}", eventName);
        }
    }

    public IReadOnlyCollection<string> ActiveSubscriptions => _activeWatchers.Keys.ToList().AsReadOnly();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (var (name, watcher) in _activeWatchers)
        {
            watcher.Stop();
            watcher.Dispose();
            _logger.LogDebug("Disposed watcher: {Name}", name);
        }
        _activeWatchers.Clear();
    }
}

/// <summary>
/// Event arguments for system events captured by WMI.
/// </summary>
public sealed class SystemEventArgs : EventArgs
{
    public string EventName { get; }
    public ManagementBaseObject RawEvent { get; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;

    public SystemEventArgs(string eventName, ManagementBaseObject rawEvent)
    {
        EventName = eventName;
        RawEvent = rawEvent;
    }

    /// <summary>
    /// Extracts the target instance from the WMI event.
    /// </summary>
    public ManagementBaseObject? GetTargetInstance()
    {
        try { return (ManagementBaseObject)RawEvent["TargetInstance"]; }
        catch { return null; }
    }
}
