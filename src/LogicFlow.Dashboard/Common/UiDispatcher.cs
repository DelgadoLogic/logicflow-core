// LogicFlow.Dashboard.Common — Thread-Safe Dispatcher & Headless Execution Wrapper
// Proprietary implementation by DelgadoLogic.Tech

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace LogicFlow.Dashboard.Common;

/// <summary>
/// Safe UI thread dispatcher wrapper that executes actions directly when running headlessly
/// (e.g. in unit tests where Application.Current is null or has no active message loop) or when already on the UI thread.
/// </summary>
public static class UiDispatcher
{
    private static readonly AsyncLocal<Action<Action>?> _dispatchOverride = new();

    /// <summary>
    /// Optional override hook for test harnesses to capture or redirect dispatcher invocations.
    /// </summary>
    public static Action<Action>? DispatchOverride
    {
        get => _dispatchOverride.Value;
        set => _dispatchOverride.Value = value;
    }

    /// <summary>
    /// True only when the WPF Application message loop has started via App.OnStartup.
    /// Prevents headless BAML unit tests from marshaling onto a temporary STA thread that has no message loop.
    /// </summary>
    public static volatile bool IsMessageLoopRunning;

    private static bool ShouldMarshalToDispatcher(Application? app)
    {
        if (!IsMessageLoopRunning)
            return false;
        if (app?.Dispatcher is not { HasShutdownStarted: false, HasShutdownFinished: false } dispatcher)
            return false;
        if (!dispatcher.Thread.IsAlive)
            return false;
        return !dispatcher.CheckAccess();
    }

    /// <summary>
    /// Executes the specified action on the UI thread, or synchronously if running headlessly or already on UI thread.
    /// </summary>
    public static void Invoke(Action action)
    {
        if (action == null) return;

        var customHook = DispatchOverride;
        if (customHook != null)
        {
            customHook(action);
            return;
        }

        var app = Application.Current;
        if (ShouldMarshalToDispatcher(app))
        {
            app!.Dispatcher.Invoke(action);
        }
        else
        {
            action();
        }
    }

    /// <summary>
    /// Asynchronously executes the specified action on the UI thread, or synchronously if running headlessly or already on UI thread.
    /// </summary>
    public static async Task InvokeAsync(Action action)
    {
        if (action == null) return;

        var customHook = DispatchOverride;
        if (customHook != null)
        {
            customHook(action);
            return;
        }

        var app = Application.Current;
        if (ShouldMarshalToDispatcher(app))
        {
            await app!.Dispatcher.InvokeAsync(action);
        }
        else
        {
            action();
        }
    }

    /// <summary>
    /// Asynchronously executes the specified function on the UI thread, returning its result.
    /// </summary>
    public static async Task<T> InvokeAsync<T>(Func<T> func)
    {
        if (func == null) throw new ArgumentNullException(nameof(func));

        var app = Application.Current;
        if (ShouldMarshalToDispatcher(app))
        {
            return await app!.Dispatcher.InvokeAsync(func);
        }

        return func();
    }
}
