using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Windows.Forms;
using LogicFlow.Dashboard;

namespace LogicFlow.Tests;

public class TrayAndSingleInstanceLifecycleTests
{
    [Fact]
    public void DarkMenuColorTable_EnforcesObsidianAndSlateGlassPalette()
    {
        var table = new DarkMenuColorTable();

        // Background is Dark Obsidian #0D1117
        Assert.Equal(Color.FromArgb(13, 17, 23), table.ToolStripDropDownBackground);
        Assert.Equal(Color.FromArgb(13, 17, 23), table.ImageMarginGradientBegin);
        Assert.Equal(Color.FromArgb(13, 17, 23), table.ImageMarginGradientEnd);

        // Hover / Selection is Dark Slate #1E293B
        Assert.Equal(Color.FromArgb(30, 41, 59), table.MenuItemSelected);
        Assert.Equal(Color.FromArgb(30, 41, 59), table.MenuItemSelectedGradientBegin);
        Assert.Equal(Color.FromArgb(30, 41, 59), table.MenuItemSelectedGradientEnd);

        // Hover border is Electric Cyan #00E5FF
        Assert.Equal(Color.FromArgb(0, 229, 255), table.MenuItemBorder);

        // Pressed / Active is Dark Slate Active #161B22
        Assert.Equal(Color.FromArgb(22, 27, 34), table.MenuItemPressedGradientBegin);
        Assert.Equal(Color.FromArgb(22, 27, 34), table.MenuItemPressedGradientEnd);

        // Border & Separator is Slate #334155
        Assert.Equal(Color.FromArgb(51, 65, 85), table.MenuBorder);
        Assert.Equal(Color.FromArgb(51, 65, 85), table.SeparatorDark);
    }

    [Fact]
    public void DarkMenuRenderer_InitializesAndRendersWithoutExceptions()
    {
        var renderer = new DarkMenuRenderer();
        Assert.NotNull(renderer);
        Assert.False(renderer.RoundedEdges);

        using var menu = new ContextMenuStrip
        {
            Renderer = renderer,
            ShowImageMargin = false,
            ShowCheckMargin = false,
            BackColor = Color.FromArgb(13, 17, 23),
            ForeColor = Color.FromArgb(226, 232, 240)
        };

        var label = new ToolStripLabel("⚡ LogicFlow v1.0.0");
        var item = new ToolStripMenuItem("⚙ Settings");
        var sep = new ToolStripSeparator();

        menu.Items.Add(label);
        menu.Items.Add(sep);
        menu.Items.Add(item);

        Assert.Equal(3, menu.Items.Count);
    }

    [Fact]
    public void DarkMenuRenderer_RendersObsidianBackgroundAndSlateHover()
    {
        var renderer = new DarkMenuRenderer();
        using var item = new ToolStripMenuItem("Test Item");
        item.Size = new Size(100, 30);

        // 1. Unselected render
        using var bmpNormal = new Bitmap(100, 30);
        using (var g = Graphics.FromImage(bmpNormal))
        {
            var args = new ToolStripItemRenderEventArgs(g, item);
            var renderMethod = typeof(DarkMenuRenderer).GetMethod("OnRenderMenuItemBackground",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            Assert.NotNull(renderMethod);
            renderMethod.Invoke(renderer, new object[] { args });
        }

        // Center pixel should be ObsidianDark #0D1117
        var pixelNormal = bmpNormal.GetPixel(50, 15);
        Assert.Equal(13, pixelNormal.R);
        Assert.Equal(17, pixelNormal.G);
        Assert.Equal(23, pixelNormal.B);

        // 2. Selected (hovered) render
        item.Select();
        using var bmpHover = new Bitmap(100, 30);
        using (var g = Graphics.FromImage(bmpHover))
        {
            var args = new ToolStripItemRenderEventArgs(g, item);
            var renderMethod = typeof(DarkMenuRenderer).GetMethod("OnRenderMenuItemBackground",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            renderMethod?.Invoke(renderer, new object[] { args });
        }

        // Center pixel should be SlateHover #1E293B
        var pixelHover = bmpHover.GetPixel(50, 15);
        Assert.Equal(30, pixelHover.R);
        Assert.Equal(41, pixelHover.G);
        Assert.Equal(59, pixelHover.B);
    }

    [Fact]
    public void DarkMenuRenderer_RendersItemTextWithoutExceptions()
    {
        var renderer = new DarkMenuRenderer();
        using var item = new ToolStripMenuItem("⚙ Settings");
        item.Size = new Size(120, 26);

        using var bmp = new Bitmap(120, 26);
        using var g = Graphics.FromImage(bmp);

        var args = new ToolStripItemTextRenderEventArgs(
            g,
            item,
            item.Text,
            new Rectangle(0, 0, 120, 26),
            Color.White,
            item.Font,
            TextFormatFlags.Left);

        var renderMethod = typeof(DarkMenuRenderer).GetMethod("OnRenderItemText",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(renderMethod);
        renderMethod.Invoke(renderer, new object[] { args });
    }

    [Fact]
    public void SingleInstance_Mutex_BlocksSecondHolder()
    {
        var testMutexName = "Local\\LogicFlow_UnitTest_Mutex_" + Guid.NewGuid().ToString("N");
        using var firstMutex = new Mutex(true, testMutexName, out bool createdFirst);
        Assert.True(createdFirst, "First instance should successfully create and own mutex");

        using var secondMutex = new Mutex(true, testMutexName, out bool createdSecond);
        Assert.False(createdSecond, "Second instance should detect mutex is already owned");
    }

    [Fact]
    public async Task SingleInstance_NamedPipe_TransmitsActivationSignal()
    {
        var pipeName = "LogicFlow_UnitTest_Pipe_" + Guid.NewGuid().ToString("N");
        var receivedSignal = false;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.In,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);

        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync(cts.Token);
            using var reader = new StreamReader(server, System.Text.Encoding.UTF8);
            var msg = await reader.ReadLineAsync(cts.Token);
            if (msg == "RESTORE")
            {
                receivedSignal = true;
            }
        }, cts.Token);

        // Connect client (server pipe already listening before Task.Run starts)
        using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.Out);
        await client.ConnectAsync(15000, cts.Token);
        using var writer = new StreamWriter(client, System.Text.Encoding.UTF8) { AutoFlush = true };
        await writer.WriteLineAsync("RESTORE");
        client.WaitForPipeDrain();

        await serverTask;
        Assert.True(receivedSignal, "Server should receive the RESTORE activation command");
    }

    [Fact]
    public void DarkMenuColorTable_ExposesDarkThemeProperties()
    {
        var table = new DarkMenuColorTable();
        Assert.Equal(Color.FromArgb(22, 27, 34), table.CheckBackground);
        Assert.Equal(Color.FromArgb(30, 41, 59), table.CheckSelectedBackground);
        Assert.Equal(Color.FromArgb(0, 229, 255), table.ButtonSelectedBorder);
    }

    [Fact]
    public void DarkMenuRenderer_OnRenderItemCheck_RendersCheckmarkWithoutException()
    {
        var renderer = new DarkMenuRenderer();
        using var item = new ToolStripMenuItem("🚀 Toggle Turbo / Boost") { Checked = true };
        using var bmp = new Bitmap(24, 24);
        using var g = Graphics.FromImage(bmp);

        var args = new ToolStripItemImageRenderEventArgs(
            g,
            item,
            new Rectangle(2, 2, 20, 20));

        var renderMethod = typeof(DarkMenuRenderer).GetMethod("OnRenderItemCheck",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(renderMethod);
        renderMethod.Invoke(renderer, new object[] { args });

        // Verify that pixels within the check area were colored (non-transparent)
        bool hasDrawnPixels = false;
        for (int x = 2; x < 22; x++)
        {
            for (int y = 2; y < 22; y++)
            {
                var pixel = bmp.GetPixel(x, y);
                if (pixel.A > 0)
                {
                    hasDrawnPixels = true;
                    break;
                }
            }
            if (hasDrawnPixels) break;
        }
        Assert.True(hasDrawnPixels, "OnRenderItemCheck should draw check box and checkmark");
    }

    [Fact]
    public void SettingsManager_SetStartWithWindows_EnactsAndSyncsRegistry()
    {
        bool taskRegistered = false;
        string? lastCreateArgs = null;
        try
        {
            // Part A: Verify elevated Scheduled Task path and duplicate HKCU\Run\LogicFlow cleanup
            SettingsManager.ScheduledTaskCommandRunner = args =>
            {
                if (args.StartsWith("/Create ", StringComparison.OrdinalIgnoreCase))
                {
                    lastCreateArgs = args;
                    taskRegistered = true;
                    return true;
                }
                if (args.StartsWith("/Delete ", StringComparison.OrdinalIgnoreCase))
                {
                    taskRegistered = false;
                    return true;
                }
                if (args.StartsWith("/Query ", StringComparison.OrdinalIgnoreCase))
                {
                    return taskRegistered;
                }
                return false;
            };

            using (var prepKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true))
            {
                prepKey?.SetValue("LogicFlow", "\"C:\\Legacy\\LogicFlow.exe\" --tray", Microsoft.Win32.RegistryValueKind.String);
            }

            Assert.True(SettingsManager.ApplyStartWithWindows(true));
            Assert.True(taskRegistered);
            Assert.NotNull(lastCreateArgs);
            Assert.Contains("/TN \"LogicFlow\"", lastCreateArgs);
            Assert.Contains("--tray", lastCreateArgs);
            Assert.Contains("/SC ONLOGON /RL HIGHEST /F", lastCreateArgs);
            Assert.True(SettingsManager.IsScheduledTaskConfigured());
            Assert.True(SettingsManager.IsStartWithWindowsConfigured());

            // Verify duplicate HKCU\Run\LogicFlow was deleted so it never double-launches or triggers UAC at login
            using (var keyAfterElevated = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false))
            {
                Assert.Null(keyAfterElevated?.GetValue("LogicFlow"));
            }

            Assert.True(SettingsManager.ApplyStartWithWindows(false));
            Assert.False(taskRegistered);
            Assert.False(SettingsManager.IsScheduledTaskConfigured());
            Assert.False(SettingsManager.IsStartWithWindowsConfigured());
        }
        finally
        {
            SettingsManager.ScheduledTaskCommandRunner = null;
        }

        // Part B: Verify default behavior in current security context
        bool enabled = SettingsManager.ApplyStartWithWindows(true);
        Assert.True(enabled, "ApplyStartWithWindows(true) should succeed");
        Assert.True(SettingsManager.IsStartWithWindowsConfigured(), "IsStartWithWindowsConfigured should return true after enable");

        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);
        Assert.NotNull(key);
        var val = key.GetValue("LogicFlow") as string;
        if (SettingsManager.IsRunningAsAdministrator())
        {
            Assert.Null(val);
        }
        else
        {
            Assert.NotNull(val);
            Assert.Contains("--tray", val);
        }

        bool disabled = SettingsManager.ApplyStartWithWindows(false);
        Assert.True(disabled, "ApplyStartWithWindows(false) should succeed");
        Assert.False(SettingsManager.IsStartWithWindowsConfigured(), "IsStartWithWindowsConfigured should return false after disable");

        using var keyAfter = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);
        Assert.Null(keyAfter?.GetValue("LogicFlow"));
    }
}
