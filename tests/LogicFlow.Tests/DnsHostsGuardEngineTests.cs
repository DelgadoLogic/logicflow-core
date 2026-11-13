// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — DnsHostsGuardEngineTests
// Comprehensive Test Suite for DNS & Hosts File Hijack Watchdog (Milestone 3)
// Covers: RFC-compliant parser mechanics, 150+ threat domain catalog matching,
// domain collision resistance, dual-path backups, atomic restore with attribute
// clearing, DNS cache invalidation, multi-vector resolver auditing, trusted DNS
// whitelist, rogue DNS flagging, and elevation resilience.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using LogicFlow.Sentinel;
using Moq;
using Xunit;

namespace LogicFlow.Tests;

public class DnsHostsGuardEngineTests
{
    private readonly Mock<IHostsFileService> _mockFileService = new();
    private readonly Mock<IDnsAdapterAuditor> _mockAdapterAuditor = new();
    private readonly Mock<IDnsCacheFlusher> _mockCacheFlusher = new();

    private DnsHostsGuardEngine CreateEngine()
    {
        return new DnsHostsGuardEngine(
            _mockFileService.Object,
            _mockAdapterAuditor.Object,
            _mockCacheFlusher.Object);
    }

    #region Suite 1: Trusted Public DNS Whitelist Validation

    [Theory]
    [InlineData("1.1.1.1", "Cloudflare")]
    [InlineData("1.0.0.1", "Cloudflare")]
    [InlineData("1.1.1.2", "Cloudflare")]
    [InlineData("1.0.0.2", "Cloudflare")]
    [InlineData("1.1.1.3", "Cloudflare")]
    [InlineData("1.0.0.3", "Cloudflare")]
    [InlineData("2606:4700:4700::1111", "Cloudflare")]
    [InlineData("2606:4700:4700::1001", "Cloudflare")]
    [InlineData("8.8.8.8", "Google")]
    [InlineData("8.8.4.4", "Google")]
    [InlineData("2001:4860:4860::8888", "Google")]
    [InlineData("2001:4860:4860::8844", "Google")]
    [InlineData("9.9.9.9", "Quad9")]
    [InlineData("149.112.112.112", "Quad9")]
    [InlineData("9.9.9.10", "Quad9")]
    [InlineData("149.112.112.10", "Quad9")]
    [InlineData("2620:fe::fe", "Quad9")]
    [InlineData("208.67.222.222", "OpenDNS")]
    [InlineData("208.67.220.220", "OpenDNS")]
    [InlineData("208.67.222.123", "OpenDNS")]
    [InlineData("2620:119:35::35", "OpenDNS")]
    [InlineData("94.140.14.14", "AdGuard")]
    [InlineData("94.140.15.15", "AdGuard")]
    [InlineData("94.140.14.15", "AdGuard")]
    [InlineData("2a10:50c0::ad1:ff", "AdGuard")]
    [InlineData("185.228.168.9", "CleanBrowsing")]
    [InlineData("185.228.169.9", "CleanBrowsing")]
    [InlineData("185.228.168.168", "CleanBrowsing")]
    [InlineData("2a0d:2a00:1::2", "CleanBrowsing")]
    [InlineData("76.76.2.0", "Control D")]
    [InlineData("76.76.10.0", "Control D")]
    [InlineData("76.76.2.1", "Control D")]
    [InlineData("2606:1a40::", "Control D")]
    public void ClassifyDnsServer_IdentifiesTrustedPublicProviders(string ip, string expectedProviderPrefix)
    {
        var result = DnsHostsGuardEngine.ClassifyDnsServer(ip);

        Assert.Equal(DnsServerCategory.TrustedPublic, result.Category);
        Assert.True(result.IsTrusted);
        Assert.Equal(ThreatSeverity.Info, result.Severity);
        Assert.Contains(expectedProviderPrefix, result.ProviderName, StringComparison.OrdinalIgnoreCase);
        Assert.Null(result.WarningMessage);
    }

    #endregion

    #region Suite 2: Private Subnet, CGNAT & Special Scope Boundaries

    [Theory]
    [InlineData("10.0.0.1", DnsServerCategory.PrivateSubnet, true)]
    [InlineData("10.255.255.254", DnsServerCategory.PrivateSubnet, true)]
    [InlineData("172.16.0.1", DnsServerCategory.PrivateSubnet, true)]
    [InlineData("172.31.255.254", DnsServerCategory.PrivateSubnet, true)]
    [InlineData("172.15.255.255", DnsServerCategory.RogueUntrustedPublic, false)] // Below RFC 1918 Class B
    [InlineData("172.32.0.1", DnsServerCategory.RogueUntrustedPublic, false)]     // Above RFC 1918 Class B
    [InlineData("192.168.1.1", DnsServerCategory.PrivateSubnet, true)]
    [InlineData("192.168.254.254", DnsServerCategory.PrivateSubnet, true)]
    [InlineData("100.64.0.1", DnsServerCategory.TailscaleCgnat, true)]
    [InlineData("100.100.100.100", DnsServerCategory.TailscaleCgnat, true)]       // Tailscale MagicDNS
    [InlineData("100.127.255.254", DnsServerCategory.TailscaleCgnat, true)]
    [InlineData("100.63.255.255", DnsServerCategory.RogueUntrustedPublic, false)] // Below CGNAT range
    [InlineData("100.128.0.1", DnsServerCategory.RogueUntrustedPublic, false)]    // Above CGNAT range
    [InlineData("169.254.1.1", DnsServerCategory.PrivateSubnet, true)]            // APIPA
    [InlineData("127.0.0.1", DnsServerCategory.LocalLoopback, true)]
    [InlineData("127.0.0.53", DnsServerCategory.LocalLoopback, true)]
    [InlineData("::1", DnsServerCategory.LocalLoopback, true)]
    [InlineData("fc00::1", DnsServerCategory.PrivateSubnet, true)]                 // IPv6 ULA
    [InlineData("fd12:3456:789a::1", DnsServerCategory.PrivateSubnet, true)]       // IPv6 ULA
    [InlineData("fe80::1", DnsServerCategory.PrivateSubnet, true)]                 // IPv6 Link-Local
    [InlineData("fe80::dead:beef%12", DnsServerCategory.PrivateSubnet, true)]      // IPv6 Link-Local with scope
    public void ClassifyDnsServer_CorrectlyClassifiesSubnetRangesAndEdges(string ip, DnsServerCategory expectedCategory, bool expectedTrusted)
    {
        var result = DnsHostsGuardEngine.ClassifyDnsServer(ip);

        Assert.Equal(expectedCategory, result.Category);
        Assert.Equal(expectedTrusted, result.IsTrusted);
    }

    #endregion

    #region Suite 3: Rogue & Untrusted Public DNS Threat Detection

    [Theory]
    [InlineData("198.51.100.25")]
    [InlineData("203.0.113.5")]
    [InlineData("45.33.32.156")]
    [InlineData("185.199.108.153")]
    [InlineData("2001:db8::53")]
    public void ClassifyDnsServer_FlagsUntrustedPublicIpsAsRogueThreats(string rogueIp)
    {
        var result = DnsHostsGuardEngine.ClassifyDnsServer(rogueIp);

        Assert.Equal(DnsServerCategory.RogueUntrustedPublic, result.Category);
        Assert.False(result.IsTrusted);
        Assert.Equal(ThreatSeverity.High, result.Severity);
        Assert.NotNull(result.WarningMessage);
        Assert.Contains(rogueIp, result.WarningMessage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-ip")]
    [InlineData("999.999.999.999")]
    [InlineData("fe80:::1")]
    public void ClassifyDnsServer_HandlesInvalidIpStringsGracefully(string invalidIp)
    {
        var result = DnsHostsGuardEngine.ClassifyDnsServer(invalidIp);

        Assert.Equal(DnsServerCategory.InvalidMalformed, result.Category);
        Assert.False(result.IsTrusted);
        Assert.Equal(ThreatSeverity.Low, result.Severity);
        Assert.NotNull(result.WarningMessage);
    }

    #endregion

    #region Suite 4: Multi-Vector Adapter Auditing & Discrepancies

    [Fact]
    public async Task AuditDnsResolversAsync_ConsolidatesAdaptersAndDetectsRogueDns()
    {
        // Arrange
        var adapters = new List<AdapterDnsAuditItem>
        {
            new()
            {
                AdapterGuid = "{84646777-6A59-4D88-B31F-787F637CDA85}",
                AdapterName = "Wi-Fi",
                Description = "Intel(R) Wi-Fi 6 AX201",
                InterfaceType = "Wireless80211",
                IsActive = true,
                DiscoverySources = new() { "WMI", "NetworkInterface", "Registry" },
                DnsServers = new()
                {
                    DnsHostsGuardEngine.ClassifyDnsServer("1.1.1.1"),
                    DnsHostsGuardEngine.ClassifyDnsServer("198.51.100.25") // Rogue!
                }
            }
        };

        _mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(adapters);

        var engine = CreateEngine();

        // Act
        var result = await engine.AuditDnsResolversAsync();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.TotalAdaptersAudited);
        Assert.Equal(2, result.TotalDnsServersFound);
        Assert.Equal(1, result.RogueDnsServersCount);
        Assert.True(result.HasRogueDns);
    }

    [Fact]
    public async Task AuditDnsResolversAsync_ReportsCleanStateWhenAllResolversTrusted()
    {
        // Arrange
        var adapters = new List<AdapterDnsAuditItem>
        {
            new()
            {
                AdapterGuid = "{11111111-2222-3333-4444-555555555555}",
                AdapterName = "Ethernet",
                Description = "Realtek PCIe GbE",
                InterfaceType = "Ethernet",
                IsActive = true,
                DiscoverySources = new() { "WMI", "NetworkInterface" },
                DnsServers = new()
                {
                    DnsHostsGuardEngine.ClassifyDnsServer("192.168.1.1"),
                    DnsHostsGuardEngine.ClassifyDnsServer("8.8.8.8")
                }
            }
        };

        _mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(adapters);

        var engine = CreateEngine();

        // Act
        var result = await engine.AuditDnsResolversAsync();

        // Assert
        Assert.False(result.HasRogueDns);
        Assert.Equal(0, result.RogueDnsServersCount);
        Assert.Equal(1, result.TotalAdaptersAudited);
        Assert.Equal(2, result.TotalDnsServersFound);
    }

    [Fact]
    public async Task AuditDnsResolversAsync_HandlesNullAdapterListGracefully()
    {
        _mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync((List<AdapterDnsAuditItem>?)null!);

        var engine = CreateEngine();
        var result = await engine.AuditDnsResolversAsync();

        Assert.NotNull(result);
        Assert.Empty(result.Adapters);
        Assert.Equal(0, result.TotalAdaptersAudited);
        Assert.False(result.HasRogueDns);
    }

    #endregion

    #region Suite 5: RFC-Compliant Hosts File Parsing

    [Fact]
    public void ParseHostsContent_StripsInlineCommentsAndParsesMultiHostLines()
    {
        string hostsContent = @"
# System Hosts File
127.0.0.1 localhost # standard loopback
::1       localhost ip6-localhost
192.168.1.50 server.local nas.local # internal hosts
# 10.0.0.5 disabled.local
";
        var entries = DnsHostsGuardEngine.ParseHostsContent(hostsContent);

        Assert.Equal(5, entries.Count);
        Assert.Contains(entries, e => e.IpAddress == "127.0.0.1" && e.Hostname == "localhost");
        Assert.Contains(entries, e => e.IpAddress == "::1" && e.Hostname == "localhost");
        Assert.Contains(entries, e => e.IpAddress == "::1" && e.Hostname == "ip6-localhost");
        Assert.Contains(entries, e => e.IpAddress == "192.168.1.50" && e.Hostname == "server.local");
        Assert.Contains(entries, e => e.IpAddress == "192.168.1.50" && e.Hostname == "nas.local");
    }

    [Fact]
    public void ParseHostsContent_HandlesTabsAndIrregularSpacing()
    {
        string content = "10.0.0.1\t\thost.internal\t  alias.internal   # comment";
        var entries = DnsHostsGuardEngine.ParseHostsContent(content);

        Assert.Equal(2, entries.Count);
        Assert.Equal("10.0.0.1", entries[0].IpAddress);
        Assert.Equal("host.internal", entries[0].Hostname);
        Assert.Equal("alias.internal", entries[1].Hostname);
    }

    [Fact]
    public void ParseHostsContent_SkipsMalformedAndInvertedLines()
    {
        string content = @"
virustotal.com 127.0.0.1
invalid-ip hostname.local
127.0.0.1
   # only a comment
";
        var entries = DnsHostsGuardEngine.ParseHostsContent(content);
        Assert.Empty(entries);
    }

    [Fact]
    public void ParseHostsContent_NormalizesTrailingDotsAndCase()
    {
        string content = "127.0.0.1 MYHOST.LOCAL.";
        var entries = DnsHostsGuardEngine.ParseHostsContent(content);

        Assert.Single(entries);
        Assert.Equal("myhost.local", entries[0].Hostname);
    }

    [Fact]
    public void ParseHostsContent_EmptyOrNullReturnsEmptyList()
    {
        Assert.Empty(DnsHostsGuardEngine.ParseHostsContent(""));
        Assert.Empty(DnsHostsGuardEngine.ParseHostsContent("   \r\n\t  "));
        Assert.Empty(DnsHostsGuardEngine.ParseHostsLines(null!));
    }

    #endregion

    #region Suite 6: Threat Intelligence Domain Catalog Detection

    [Theory]
    [InlineData("127.0.0.1", "update.microsoft.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("0.0.0.0", "definitionupdates.microsoft.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("::1", "wdcp.microsoft.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("::", "smartscreen.microsoft.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("127.0.0.1", "virustotal.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("127.0.0.1", "malwarebytes.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("127.0.0.1", "crowdstrike.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    [InlineData("127.0.0.1", "sentinelone.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySinkhole)]
    public void EvaluateEntry_DetectsSecurityDomainSinkhole(string ip, string host, ThreatSeverity expectedSeverity, HostsThreatCategory expectedCat)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = host };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.True(evaluated.IsSuspicious);
        Assert.Equal(expectedSeverity, evaluated.Severity);
        Assert.Equal(expectedCat, evaluated.Category);
        Assert.Contains("sinkhole", evaluated.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("198.51.100.1", "virustotal.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySpoofingRedirect)]
    [InlineData("198.51.100.1", "download.windowsupdate.com", ThreatSeverity.Critical, HostsThreatCategory.SecuritySpoofingRedirect)]
    public void EvaluateEntry_DetectsSecuritySpoofingRedirect(string ip, string host, ThreatSeverity expectedSeverity, HostsThreatCategory expectedCat)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = host };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.True(evaluated.IsSuspicious);
        Assert.Equal(expectedSeverity, evaluated.Severity);
        Assert.Equal(expectedCat, evaluated.Category);
        Assert.Contains("redirect", evaluated.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("198.51.100.1", "paypal.com", ThreatSeverity.Critical, HostsThreatCategory.FinancialPhishingRedirect)]
    [InlineData("198.51.100.1", "chase.com", ThreatSeverity.Critical, HostsThreatCategory.FinancialPhishingRedirect)]
    [InlineData("198.51.100.1", "binance.com", ThreatSeverity.Critical, HostsThreatCategory.FinancialPhishingRedirect)]
    [InlineData("198.51.100.1", "coinbase.com", ThreatSeverity.Critical, HostsThreatCategory.FinancialPhishingRedirect)]
    [InlineData("198.51.100.1", "metamask.io", ThreatSeverity.Critical, HostsThreatCategory.FinancialPhishingRedirect)]
    [InlineData("198.51.100.1", "login.microsoftonline.com", ThreatSeverity.Critical, HostsThreatCategory.FinancialPhishingRedirect)]
    public void EvaluateEntry_DetectsFinancialPhishingRedirect(string ip, string host, ThreatSeverity expectedSeverity, HostsThreatCategory expectedCat)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = host };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.True(evaluated.IsSuspicious);
        Assert.Equal(expectedSeverity, evaluated.Severity);
        Assert.Equal(expectedCat, evaluated.Category);
        Assert.Contains("redirect", evaluated.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("127.0.0.1", "bankofamerica.com", ThreatSeverity.High, HostsThreatCategory.FinancialAccessBlock)]
    [InlineData("0.0.0.0", "wellsfargo.com", ThreatSeverity.High, HostsThreatCategory.FinancialAccessBlock)]
    public void EvaluateEntry_DetectsFinancialAccessBlock(string ip, string host, ThreatSeverity expectedSeverity, HostsThreatCategory expectedCat)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = host };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.True(evaluated.IsSuspicious);
        Assert.Equal(expectedSeverity, evaluated.Severity);
        Assert.Equal(expectedCat, evaluated.Category);
    }

    [Theory]
    [InlineData("198.51.100.1", "google.com", ThreatSeverity.High, HostsThreatCategory.SearchAdwareHijack)]
    [InlineData("198.51.100.1", "bing.com", ThreatSeverity.High, HostsThreatCategory.SearchAdwareHijack)]
    [InlineData("127.0.0.1", "google.com", ThreatSeverity.Medium, HostsThreatCategory.SearchAccessBlock)]
    public void EvaluateEntry_DetectsSearchEngineThreats(string ip, string host, ThreatSeverity expectedSeverity, HostsThreatCategory expectedCat)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = host };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.True(evaluated.IsSuspicious);
        Assert.Equal(expectedSeverity, evaluated.Severity);
        Assert.Equal(expectedCat, evaluated.Category);
    }

    [Fact]
    public void EvaluateEntry_DistinguishesActiveAdwareFromSinkholedAdware()
    {
        var activeEntry = new HostsEntry { IpAddress = "198.51.100.1", Hostname = "search.conduit.com" };
        var evaluatedActive = DnsHostsGuardEngine.EvaluateHostsEntry(activeEntry);
        Assert.True(evaluatedActive.IsSuspicious);
        Assert.Equal(ThreatSeverity.High, evaluatedActive.Severity);
        Assert.Equal(HostsThreatCategory.AdwareDomainActive, evaluatedActive.Category);

        var sinkholeEntry = new HostsEntry { IpAddress = "0.0.0.0", Hostname = "search.conduit.com" };
        var evaluatedSinkhole = DnsHostsGuardEngine.EvaluateHostsEntry(sinkholeEntry);
        Assert.False(evaluatedSinkhole.IsSuspicious);
        Assert.Equal(ThreatSeverity.Info, evaluatedSinkhole.Severity);
        Assert.Equal(HostsThreatCategory.AdwareDomainSinkholed, evaluatedSinkhole.Category);
    }

    [Theory]
    [InlineData("127.0.0.1", "notgoogle.com")]
    [InlineData("127.0.0.1", "evildowngoogle.com")]
    [InlineData("127.0.0.1", "purchase.com")]
    [InlineData("127.0.0.1", "fakevirustotal.com")]
    public void EvaluateEntry_DoesNotFlagSuffixCollisions(string ip, string nonCollidingHost)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = nonCollidingHost };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.False(evaluated.IsSuspicious);
        Assert.Equal(HostsThreatCategory.CustomMapping, evaluated.Category);
    }

    [Theory]
    [InlineData("127.0.0.1", "sub.google.com")]
    [InlineData("127.0.0.1", "portal.chase.com")]
    [InlineData("127.0.0.1", "api.virustotal.com")]
    public void EvaluateEntry_FlagsLegitimateSubdomainsOfThreats(string ip, string subdomain)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = subdomain };
        var evaluated = DnsHostsGuardEntry(entry);

        Assert.True(evaluated.IsSuspicious);
    }

    private static HostsEntry DnsHostsGuardEntry(HostsEntry entry) =>
        DnsHostsGuardEngine.EvaluateHostsEntry(entry);

    [Theory]
    [InlineData("127.0.0.1", "localhost", HostsThreatCategory.BenignLocalMapping, false)]
    [InlineData("::1", "localhost", HostsThreatCategory.BenignLocalMapping, false)]
    [InlineData("10.0.0.1", "internal.corp", HostsThreatCategory.CustomMapping, false)]
    [InlineData("192.168.1.50", "nas.home", HostsThreatCategory.CustomMapping, false)]
    [InlineData("198.51.100.1", "randomunlisteddomain.com", HostsThreatCategory.ExternalPublicRedirect, true)]
    public void EvaluateEntry_CorrectlyCategorizesBenignAndCustomMappings(string ip, string host, HostsThreatCategory expectedCat, bool expectedSuspicious)
    {
        var entry = new HostsEntry { IpAddress = ip, Hostname = host };
        var evaluated = DnsHostsGuardEngine.EvaluateHostsEntry(entry);

        Assert.Equal(expectedCat, evaluated.Category);
        Assert.Equal(expectedSuspicious, evaluated.IsSuspicious);
    }

    #endregion

    #region Suite 7: Dual Backup, Atomic Restore, Attributes & Elevation

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_ClearsAttributesAndFlushesDns()
    {
        // Arrange
        _mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
        _mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
        _mockFileService.Setup(f => f.GetAttributes(It.IsAny<string>()))
            .Returns(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);
        _mockFileService.Setup(f => f.CreateSystemBackup(It.IsAny<string>()))
            .Returns(@"C:\Windows\System32\drivers\etc\hosts.bak.20260822");
        _mockFileService.Setup(f => f.CreateUserAppDataBackup(It.IsAny<string>()))
            .Returns(@"C:\Users\Admin\AppData\Local\DelgadoLogic\LogicFlow\Backups\hosts\hosts.bak.20260822");
        _mockCacheFlusher.Setup(c => c.FlushResolverCache()).Returns(true);

        var engine = CreateEngine();

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.True(result.Success);
        Assert.False(result.RequiresElevation);
        Assert.True(result.CacheFlushed);
        Assert.True(result.SystemBackupCreated);
        Assert.True(result.UserBackupCreated);
        _mockFileService.Verify(f => f.SetAttributes(It.IsAny<string>(), FileAttributes.Normal), Times.AtLeastOnce);
        _mockFileService.Verify(f => f.ReplaceFile(It.IsAny<string>(), @"C:\Windows\System32\drivers\etc\hosts", null), Times.Once);
        _mockCacheFlusher.Verify(c => c.FlushResolverCache(), Times.Once);
    }

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_HandlesUnauthorizedAccess_SetsRequiresElevation()
    {
        // Arrange
        _mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
        _mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
        _mockFileService.Setup(f => f.ReplaceFile(It.IsAny<string>(), It.IsAny<string>(), null))
            .Throws(new UnauthorizedAccessException("Access to path is denied."));

        var engine = CreateEngine();

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Elevation required", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_HandlesSecurityException_SetsRequiresElevation()
    {
        // Arrange
        _mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
        _mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
        _mockFileService.Setup(f => f.ReplaceFile(It.IsAny<string>(), It.IsAny<string>(), null))
            .Throws(new SecurityException("Security access denied."));

        var engine = CreateEngine();

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.False(result.Success);
        Assert.True(result.RequiresElevation);
        Assert.Contains("Security access denied", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RestoreDefaultHostsFileAsync_WhenHostsFileDoesNotExist_MovesStagedFileDirectly()
    {
        // Arrange
        _mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
        _mockFileService.Setup(f => f.FileExists(@"C:\Windows\System32\drivers\etc\hosts")).Returns(false);
        _mockCacheFlusher.Setup(c => c.FlushResolverCache()).Returns(true);

        var engine = CreateEngine();

        // Act
        var result = await engine.RestoreDefaultHostsFileAsync();

        // Assert
        Assert.True(result.Success);
        Assert.False(result.RequiresElevation);
        _mockFileService.Verify(f => f.MoveFile(It.IsAny<string>(), @"C:\Windows\System32\drivers\etc\hosts"), Times.Once);
    }

    [Fact]
    public void HostsRestoreResult_ImplicitBoolOperator_ReturnsCorrectValue()
    {
        var ok = HostsRestoreResult.Ok(@"C:\hosts", null, null, true);
        var fail = HostsRestoreResult.Fail(@"C:\hosts", "Error");
        HostsRestoreResult? nullResult = null;

        bool boolOk = ok;
        bool boolFail = fail;
        bool boolNull = nullResult!;

        Assert.True(boolOk);
        Assert.False(boolFail);
        Assert.False(boolNull);
    }

    #endregion

    #region Suite 8: Full Engine End-to-End AuditAsync Smoke & Mock Tests

    [Fact]
    public async Task AuditAsync_LiveSystem_ReturnsValidDnsHostsReport()
    {
        var guard = new DnsHostsGuardEngine();
        var report = await guard.AuditAsync();

        Assert.NotNull(report);
        Assert.NotNull(report.SuspiciousEntries);
        Assert.NotNull(report.NetworkAdapters);
        Assert.NotNull(report.AllEntries);
        Assert.NotNull(report.ResolverAudit);
        Assert.False(string.IsNullOrWhiteSpace(report.HostsFilePath));
    }

    [Fact]
    public async Task AuditAsync_MockedInfectedHosts_CalculatesAccurateCounts()
    {
        // Arrange
        string infectedHosts = @"
# Corp hosts
127.0.0.1 localhost
127.0.0.1 update.microsoft.com # Sinkhole (Critical)
198.51.100.1 paypal.com        # Phishing (Critical)
198.51.100.2 google.com        # Hijack (High)
127.0.0.1 bing.com             # Block (Medium)
198.51.100.3 customdomain.com  # External (Medium)
10.0.0.1 internal.corp         # Benign (Info)
";
        _mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
        _mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);
        _mockFileService.Setup(f => f.ReadAllLines(It.IsAny<string>()))
            .Returns(infectedHosts.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None));

        _mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AdapterDnsAuditItem>());

        var engine = CreateEngine();

        // Act
        var report = await engine.AuditAsync();

        // Assert
        Assert.NotNull(report);
        Assert.True(report.HasSuspiciousRedirects);
        Assert.True(report.HasThreats);
        Assert.Equal(7, report.TotalHostsEntries);
        Assert.Equal(5, report.SuspiciousEntries.Count);
        Assert.Equal(2, report.CriticalCount); // update.microsoft.com & paypal.com
        Assert.Equal(1, report.HighCount);     // google.com
        Assert.Equal(2, report.MediumCount);   // bing.com & customdomain.com
        Assert.Equal(0, report.LowCount);
    }

    [Fact]
    public async Task AuditAsync_WhenHostsFileDoesNotExist_ReturnsGracefulReport()
    {
        _mockFileService.Setup(f => f.GetHostsPath()).Returns(@"C:\Windows\System32\drivers\etc\hosts");
        _mockFileService.Setup(f => f.FileExists(It.IsAny<string>())).Returns(false);
        _mockAdapterAuditor.Setup(a => a.AuditAdaptersAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<AdapterDnsAuditItem>());

        var engine = CreateEngine();
        var report = await engine.AuditAsync();

        Assert.NotNull(report);
        Assert.False(report.HostsFileExists);
        Assert.Equal(0, report.TotalHostsEntries);
        Assert.Empty(report.SuspiciousEntries);
        Assert.False(report.HasSuspiciousRedirects);
    }

    #endregion
}
