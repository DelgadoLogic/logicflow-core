// LogicFlow.Sentinel — Unit Tests
// Tests vulnerability scanner, network scanner models, and startup auditor.

using LogicFlow.Sentinel;
using Microsoft.Extensions.Logging;
using Moq;

namespace LogicFlow.Tests;

public class SentinelTests
{
    private readonly Mock<ILogger<VulnerabilityScanner>> _vulnLogger = new();
    private readonly Mock<ILogger<NetworkScanner>> _netLogger = new();
    private readonly Mock<ILogger<StartupAuditor>> _startupLogger = new();
    private readonly Mock<ILogger<PrivacyScrubber>> _scrubLogger = new();
    private readonly Mock<ILogger<RemediationEngine>> _remLogger = new();

    // ── VulnerabilityScanner Tests ────────────────────────────────────────

    [Fact]
    public void VulnerabilityScanner_CanInstantiate()
    {
        var scanner = new VulnerabilityScanner(_vulnLogger.Object);
        Assert.NotNull(scanner);
    }

    [Fact]
    public async Task VulnerabilityScanner_ScanAsync_ReturnsResult()
    {
        var scanner = new VulnerabilityScanner(_vulnLogger.Object);
        var result = await scanner.ScanAsync();

        Assert.NotNull(result);
        Assert.True(result.ScannedAt > DateTimeOffset.MinValue);
        Assert.NotNull(result.InstalledUpdates);
        Assert.NotNull(result.Vulnerabilities);
        Assert.NotNull(result.ExposedServices);
        Assert.NotNull(result.TelemetryStatus);
    }

    // ── NetworkScanner Tests ──────────────────────────────────────────────

    [Fact]
    public void NetworkScanner_CanInstantiate()
    {
        var scanner = new NetworkScanner(_netLogger.Object);
        Assert.NotNull(scanner);
    }

    [Fact]
    public async Task NetworkScanner_FullScan_ReturnsReport()
    {
        var scanner = new NetworkScanner(_netLogger.Object);
        var report = await scanner.FullScanAsync();

        Assert.NotNull(report);
        Assert.True(report.ScannedAt > DateTimeOffset.MinValue);
        Assert.InRange(report.RiskScore, 0, 100);
        Assert.NotNull(report.OpenPorts);
        Assert.NotNull(report.ArpDevices);
        Assert.NotNull(report.DnsLeakResults);
        Assert.NotNull(report.FirewallStatus);
        Assert.NotNull(report.OpenShares);
        Assert.NotNull(report.WifiSecurity);
        Assert.NotNull(report.RdpExposure);
        Assert.NotNull(report.UpnpStatus);
        Assert.NotNull(report.SmbV1Status);
        Assert.NotNull(report.WinRmStatus);
    }

    // ── StartupAuditor Tests ──────────────────────────────────────────────

    [Fact]
    public void StartupAuditor_CanInstantiate()
    {
        var auditor = new StartupAuditor(_startupLogger.Object);
        Assert.NotNull(auditor);
    }

    [Fact]
    public void StartupAuditor_Audit_ReturnsReport()
    {
        var auditor = new StartupAuditor(_startupLogger.Object);
        var report = auditor.Audit();

        Assert.NotNull(report);
        Assert.True(report.ScannedAt > DateTimeOffset.MinValue);
        Assert.NotNull(report.Entries);
        Assert.True(report.TotalEntries >= 0);
    }

    // ── PrivacyScrubber Tests ─────────────────────────────────────────────

    [Fact]
    public void PrivacyScrubber_CanInstantiate()
    {
        var scrubber = new PrivacyScrubber(_scrubLogger.Object);
        Assert.NotNull(scrubber);
    }

    // ── RemediationEngine Tests ───────────────────────────────────────────

    [Fact]
    public void RemediationEngine_CanInstantiate()
    {
        var engine = new RemediationEngine(_remLogger.Object);
        Assert.NotNull(engine);
    }

    [Fact]
    public async Task RemediationEngine_DryRun_DoesNotModifySystem()
    {
        var engine = new RemediationEngine(_remLogger.Object);

        // Create a fake scan report with all findings
        var fakeReport = new NetworkScanReport
        {
            SmbV1Status = new SmbV1Result { IsEnabled = true },
            FirewallStatus = new FirewallStatus { IsDisabled = true },
            RdpExposure = new RdpExposureResult { IsExposed = true },
            UpnpStatus = new UpnpStatus { IsEnabled = true },
            WinRmStatus = new WinRmResult { IsEnabled = true },
            OpenPorts = [new OpenPortFinding { Port = 3389, Service = "RDP", Severity = FindingSeverity.Critical }]
        };

        var report = await engine.AutoRemediateAsync(fakeReport, dryRun: true);

        Assert.NotNull(report);
        Assert.True(report.TotalActions > 0);
        Assert.True(report.Actions.All(a => a.DryRun));
        Assert.True(report.Actions.All(a => a.Success));
    }

    // ── Data Model Tests ──────────────────────────────────────────────────

    [Theory]
    [InlineData(FindingSeverity.Info)]
    [InlineData(FindingSeverity.Low)]
    [InlineData(FindingSeverity.Medium)]
    [InlineData(FindingSeverity.High)]
    [InlineData(FindingSeverity.Critical)]
    public void FindingSeverity_AllValuesExist(FindingSeverity severity)
    {
        Assert.True(Enum.IsDefined(severity));
    }

    [Fact]
    public void VulnSeverity_AllValuesExist()
    {
        Assert.Equal(4, Enum.GetValues<VulnSeverity>().Length);
    }

    [Fact]
    public void ScrubReport_TotalsAreComputed()
    {
        var report = new ScrubReport
        {
            Targets =
            [
                new ScrubTarget { BytesCleared = 1024, FilesCleared = 10 },
                new ScrubTarget { BytesCleared = 2048, FilesCleared = 20 }
            ]
        };

        Assert.Equal(3072, report.TotalBytesCleared);
        Assert.Equal(30, report.TotalFilesCleared);
    }

    [Fact]
    public void OpenPortFinding_RecordEquality()
    {
        var a = new OpenPortFinding { Port = 445, Service = "SMB", Severity = FindingSeverity.Critical };
        var b = new OpenPortFinding { Port = 445, Service = "SMB", Severity = FindingSeverity.Critical };

        Assert.Equal(a, b);
    }

    [Fact]
    public void StartupClassification_AllValuesExist()
    {
        Assert.Equal(3, Enum.GetValues<StartupClassification>().Length);
    }
}
