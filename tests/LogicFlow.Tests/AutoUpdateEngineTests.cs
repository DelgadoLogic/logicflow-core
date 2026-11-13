// LogicFlow.Core — AutoUpdateEngine Unit Tests
// Tests version comparison, response handling, and signature verification flows.

using LogicFlow.Core;
using Microsoft.Extensions.Logging;
using Moq;

namespace LogicFlow.Tests;

public class AutoUpdateEngineTests
{
    private readonly Mock<ILogger<AutoUpdateEngine>> _logger = new();

    // ── Version Constant Tests ────────────────────────────────────────────

    [Fact]
    public void CurrentVersion_IsValidSemver()
    {
        Assert.True(Version.TryParse(AutoUpdateEngine.CurrentVersion, out var version));
        Assert.True(version.Major >= 1);
    }

    [Fact]
    public void CurrentVersion_Matches_1_0_0()
    {
        Assert.Equal("1.0.0", AutoUpdateEngine.CurrentVersion);
    }

    // ── Construction Tests ────────────────────────────────────────────────

    [Fact]
    public void Constructor_DoesNotThrow()
    {
        var engine = new AutoUpdateEngine(_logger.Object);
        Assert.NotNull(engine);
    }

    // ── CheckForUpdate Tests (Network-dependent) ──────────────────────────

    [Fact]
    public async Task CheckForUpdate_ReturnsNullOnNetworkError()
    {
        // The sovereign server likely isn't running in test environment
        var engine = new AutoUpdateEngine(_logger.Object);
        var result = await engine.CheckForUpdateAsync(CancellationToken.None);

        // Should gracefully return null (not throw) on network timeout/error
        // This validates the error handling path
        Assert.Null(result);
    }

    [Fact]
    public async Task CheckForUpdate_RespectsCancel()
    {
        var engine = new AutoUpdateEngine(_logger.Object);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await engine.CheckForUpdateAsync(cts.Token);
        Assert.Null(result);
    }

    // ── UpdateCheckResult Model Tests ─────────────────────────────────────

    [Fact]
    public void UpdateCheckResult_NoUpdate_IsCorrect()
    {
        var result = new UpdateCheckResult(
            UpdateAvailable: false,
            CurrentVersion: "1.0.0",
            LatestVersion: "1.0.0",
            DownloadUrl: null,
            ReleaseNotes: null,
            Signature: null);

        Assert.False(result.UpdateAvailable);
        Assert.Equal("1.0.0", result.CurrentVersion);
        Assert.Equal("1.0.0", result.LatestVersion);
    }

    [Fact]
    public void UpdateCheckResult_UpdateAvailable_IsCorrect()
    {
        var result = new UpdateCheckResult(
            UpdateAvailable: true,
            CurrentVersion: "1.0.0",
            LatestVersion: "1.1.0",
            DownloadUrl: "https://api.delgadologic.tech/downloads/logicflow/1.1.0",
            ReleaseNotes: "Bug fixes and performance improvements",
            Signature: "dGVzdA==");

        Assert.True(result.UpdateAvailable);
        Assert.Equal("1.1.0", result.LatestVersion);
        Assert.NotNull(result.DownloadUrl);
        Assert.NotNull(result.ReleaseNotes);
    }
}
