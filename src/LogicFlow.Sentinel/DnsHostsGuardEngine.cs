// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Sentinel – DnsHostsGuardEngine
// Network Integrity & Hosts File Hijack Watchdog
// Scans the Windows hosts file for malicious domain redirects / telemetry blockers,
// audits active adapter DNS configurations across WMI, NetIf, and Registry,
// and provides safe dual-path backup & atomic restore with DNS cache flushing.
// Proprietary implementation by DelgadoLogic.Tech
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Sentinel
{
    #region Domain Enums & Models

    /// <summary>
    /// Categorization for detected hosts file entries.
    /// </summary>
    public enum HostsThreatCategory
    {
        None,
        BenignLocalMapping,
        CustomMapping,
        SecuritySinkhole,
        SecuritySpoofingRedirect,
        FinancialPhishingRedirect,
        FinancialAccessBlock,
        SearchAdwareHijack,
        SearchAccessBlock,
        AdwareDomainActive,
        AdwareDomainSinkholed,
        ExternalPublicRedirect
    }

    /// <summary>
    /// Categorization for audited network DNS resolver IP addresses.
    /// </summary>
    public enum DnsServerCategory
    {
        TrustedPublic,
        PrivateSubnet,
        TailscaleCgnat,
        LocalLoopback,
        RogueUntrustedPublic,
        InvalidMalformed
    }

    /// <summary>
    /// Represents a parsed and analyzed mapping from the Windows hosts file.
    /// </summary>
    public sealed class HostsEntry
    {
        public int LineNumber { get; init; }
        public string IpAddress { get; init; } = "";
        public string Hostname { get; init; } = "";
        public bool IsSuspicious { get; set; }
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Info;
        public HostsThreatCategory Category { get; set; } = HostsThreatCategory.None;
        public string? Reason { get; set; }
        public bool IsLoopback { get; set; }
        public bool IsBlackhole { get; set; }
        public bool IsPrivateIp { get; set; }
        public string? MatchedThreatDomain { get; set; }
    }

    /// <summary>
    /// Legacy/backward-compatible summary representation of adapter DNS info.
    /// </summary>
    public sealed class AdapterDnsInfo
    {
        public string AdapterName { get; init; } = "";
        public string Description { get; init; } = "";
        public List<string> DnsServers { get; init; } = new();
    }

    /// <summary>
    /// Classification details for an individual DNS server IP address.
    /// </summary>
    public sealed class DnsServerClassification
    {
        public string IpAddress { get; init; } = "";
        public DnsServerCategory Category { get; init; }
        public string ProviderName { get; init; } = "";
        public bool IsTrusted { get; init; }
        public ThreatSeverity Severity { get; init; } = ThreatSeverity.Info;
        public string? WarningMessage { get; init; }
    }

    /// <summary>
    /// Detailed multi-vector audit result for a network interface adapter.
    /// </summary>
    public sealed class AdapterDnsAuditItem
    {
        public string AdapterGuid { get; init; } = "";
        public string AdapterName { get; init; } = "";
        public string Description { get; init; } = "";
        public string InterfaceType { get; init; } = "";
        public bool IsActive { get; init; }
        public bool IsDhcpEnabled { get; init; }
        public List<DnsServerClassification> DnsServers { get; init; } = new();
        public List<string> DiscoverySources { get; init; } = new();
        public bool HasRogueDns => DnsServers.Any(s => !s.IsTrusted);
        public string? DiscrepancyWarning { get; init; }
    }

    /// <summary>
    /// Consolidated audit report for all system DNS resolvers.
    /// </summary>
    public sealed class DnsResolverAuditResult
    {
        public List<AdapterDnsAuditItem> Adapters { get; init; } = new();
        public int TotalAdaptersAudited => Adapters.Count;
        public int TotalDnsServersFound => Adapters.Sum(a => a.DnsServers.Count);
        public int RogueDnsServersCount => Adapters.Sum(a => a.DnsServers.Count(s => !s.IsTrusted));
        public bool HasRogueDns => RogueDnsServersCount > 0;
        public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Comprehensive audit report for DNS and hosts file watchdog.
    /// </summary>
    public sealed class DnsHostsGuardReport
    {
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
        public string HostsFilePath { get; init; } = "";
        public bool HostsFileExists { get; init; }
        public int TotalHostsEntries { get; set; }
        public int TotalLinesScanned { get; set; }
        public List<HostsEntry> AllEntries { get; init; } = new();
        public List<HostsEntry> SuspiciousEntries { get; init; } = new();
        public List<AdapterDnsInfo> NetworkAdapters { get; init; } = new();
        public DnsResolverAuditResult ResolverAudit { get; init; } = new();
        public bool HasSuspiciousRedirects => SuspiciousEntries.Count > 0;
        public bool HasRogueDns => ResolverAudit?.HasRogueDns ?? false;
        public bool HasThreats => HasSuspiciousRedirects || HasRogueDns;
        public int CriticalCount => SuspiciousEntries.Count(e => e.Severity == ThreatSeverity.Critical);
        public int HighCount => SuspiciousEntries.Count(e => e.Severity == ThreatSeverity.High);
        public int MediumCount => SuspiciousEntries.Count(e => e.Severity == ThreatSeverity.Medium);
        public int LowCount => SuspiciousEntries.Count(e => e.Severity == ThreatSeverity.Low);
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Structured result of a hosts file restore operation.
    /// </summary>
    public sealed class HostsRestoreResult
    {
        public bool Success { get; init; }
        public string Action { get; init; } = "RestoreDefaultHosts";
        public string HostsFilePath { get; init; } = "";
        public string? SystemBackupPath { get; init; }
        public string? UserBackupPath { get; init; }
        public bool SystemBackupCreated => !string.IsNullOrEmpty(SystemBackupPath);
        public bool UserBackupCreated => !string.IsNullOrEmpty(UserBackupPath);
        public bool CacheFlushed { get; init; }
        public string? CacheFlushMethod { get; init; }
        public bool RequiresElevation { get; init; }
        public string? ErrorMessage { get; init; }
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

        public static HostsRestoreResult Ok(
            string hostsPath,
            string? sysBackup,
            string? userBackup,
            bool cacheFlushed,
            string? flushMethod = "PInvoke") =>
            new()
            {
                Success = true,
                HostsFilePath = hostsPath,
                SystemBackupPath = sysBackup,
                UserBackupPath = userBackup,
                CacheFlushed = cacheFlushed,
                CacheFlushMethod = flushMethod
            };

        public static HostsRestoreResult Fail(
            string hostsPath,
            string errorMessage,
            bool requiresElevation = false,
            string? sysBackup = null,
            string? userBackup = null) =>
            new()
            {
                Success = false,
                HostsFilePath = hostsPath,
                ErrorMessage = errorMessage,
                RequiresElevation = requiresElevation,
                SystemBackupPath = sysBackup,
                UserBackupPath = userBackup
            };

        public static implicit operator bool(HostsRestoreResult? result) => result?.Success ?? false;
    }

    #endregion

    #region Service Interfaces

    /// <summary>
    /// Abstraction for hosts file system operations, backups, and attribute management.
    /// </summary>
    public interface IHostsFileService
    {
        string GetHostsPath();
        bool FileExists(string path);
        string[] ReadAllLines(string path);
        string ReadAllText(string path);
        void WriteAllText(string path, string content);
        void ReplaceFile(string sourceFile, string targetFile, string? backupFile);
        void MoveFile(string sourceFile, string targetFile);
        void DeleteFile(string path);
        FileAttributes GetAttributes(string path);
        void SetAttributes(string path, FileAttributes attributes);
        string? CreateUserAppDataBackup(string sourcePath);
        string? CreateSystemBackup(string sourcePath);
    }

    /// <summary>
    /// Abstraction for network adapter DNS resolution queries across WMI, NetIf, and Registry.
    /// </summary>
    public interface IDnsAdapterAuditor
    {
        Task<List<AdapterDnsAuditItem>> AuditAdaptersAsync(CancellationToken ct = default);
    }

    /// <summary>
    /// Abstraction for DNS resolver cache flushing.
    /// </summary>
    public interface IDnsCacheFlusher
    {
        bool FlushResolverCache();
        Task<bool> FlushResolverCacheAsync(CancellationToken ct = default);
    }

    /// <summary>
    /// Threat domain intelligence catalog interface.
    /// </summary>
    public interface IThreatDomainCatalog
    {
        bool IsSecurityDomain(string host, out string? matchedDomain);
        bool IsFinancialDomain(string host, out string? matchedDomain);
        bool IsSearchDomain(string host, out string? matchedDomain);
        bool IsAdwareDomain(string host, out string? matchedDomain);
    }

    #endregion

    #region Threat Intelligence Catalog

    /// <summary>
    /// 150+ Domain Threat Intelligence Catalog covering AV/EDR sinkholes, Defender telemetry endpoints,
    /// banking/crypto portals, search engines, and known adware redirection targets.
    /// </summary>
    public sealed class ThreatDomainCatalog : IThreatDomainCatalog
    {
        public static readonly ThreatDomainCatalog Instance = new();

        private static readonly HashSet<string> SecurityDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            // Microsoft Defender & Windows Update
            "definitionupdates.microsoft.com",
            "wdcp.microsoft.com",
            "wdcpalt.microsoft.com",
            "smartscreen.microsoft.com",
            "smartscreen-prod.microsoft.com",
            "windowsupdate.com",
            "update.microsoft.com",
            "download.windowsupdate.com",
            "download.microsoft.com",
            "securitycenter.microsoft.com",
            "msftncsi.com",
            "fe3.delivery.mp.microsoft.com",
            "fe2.update.microsoft.com",
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "security.microsoft.com",
            "security.windows.com",
            "protection.office.com",

            // Antivirus & EDR Vendors
            "virustotal.com",
            "virustotal.net",
            "malwarebytes.com",
            "malwarebytes.org",
            "kaspersky.com",
            "kaspersky-labs.com",
            "sophos.com",
            "eset.com",
            "esetnod32.ru",
            "bitdefender.com",
            "bitdefender.net",
            "crowdstrike.com",
            "sentinelone.com",
            "sentinelone.net",
            "bleepingcomputer.com",
            "trendmicro.com",
            "symantec.com",
            "broadcom.com",
            "avast.com",
            "avg.com",
            "norton.com",
            "mcafee.com",
            "carbonblack.com",
            "fireeye.com",
            "mandiant.com",
            "trellix.com",
            "fortinet.com",
            "fortiguard.com",
            "paloaltonetworks.com",
            "f-secure.com",
            "withsecure.com",
            "clamav.net",
            "drweb.com",
            "emsisoft.com",
            "hitmanpro.com",
            "avira.com",
            "k7computing.com",
            "totalav.com",
            "cylance.com",
            "webroot.com",
            "zonealarm.com",
            "threatdown.com",

            // CRL, OCSP & Threat Intelligence Feeds
            "crl.microsoft.com",
            "ocsp.digicert.com",
            "ocsp.sectigo.com",
            "ocsp.verisign.com",
            "crl.identrust.com",
            "crl.comodoca.com",
            "letsencrypt.org",
            "abuse.ch",
            "urlhaus.abuse.ch",
            "threatcrowd.org",
            "hybrid-analysis.com",
            "any.run",
            "shodan.io",
            "censys.io",
            "talosintelligence.com"
        };

        private static readonly HashSet<string> FinancialDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            // Major Banking Institutions
            "chase.com",
            "bankofamerica.com",
            "wellsfargo.com",
            "citi.com",
            "citibank.com",
            "capitalone.com",
            "usbank.com",
            "pnc.com",
            "tdbank.com",
            "td.com",
            "schwab.com",
            "fidelity.com",
            "vanguard.com",
            "americanexpress.com",
            "discover.com",
            "barclays.co.uk",
            "barclays.com",
            "hsbc.com",
            "hsbc.co.uk",
            "santander.com",
            "santanderbank.com",
            "standardchartered.com",
            "ubs.com",
            "bnpparibas.com",
            "deutsche-bank.de",
            "bmo.com",
            "scotiabank.com",
            "rbc.com",
            "rbcroyalbank.com",
            "cibc.com",
            "navyfederal.org",
            "usaa.com",
            "huntington.com",
            "regions.com",
            "key.com",
            "ally.com",
            "sofi.com",

            // FinTech & Payment Processors
            "paypal.com",
            "venmo.com",
            "stripe.com",
            "square.com",
            "squareup.com",
            "cash.app",
            "wise.com",
            "transferwise.com",
            "revolut.com",
            "zellepay.com",
            "payoneer.com",
            "klarna.com",
            "affirm.com",
            "westernunion.com",
            "moneygram.com",

            // Cryptocurrency Exchanges & Web3
            "binance.com",
            "binance.us",
            "coinbase.com",
            "kraken.com",
            "gemini.com",
            "kucoin.com",
            "bybit.com",
            "okx.com",
            "bitfinex.com",
            "bitstamp.net",
            "crypto.com",
            "robinhood.com",
            "metamask.io",
            "uniswap.org",
            "opensea.io",
            "ledger.com",
            "trezor.io",
            "blockchain.com",
            "pancakeswap.finance",
            "sushiswap.org",
            "curve.fi",
            "etherscan.io",
            "bscscan.com",
            "phantom.app",
            "solflare.com",

            // Identity, SSO & Cloud Auth
            "login.microsoftonline.com",
            "account.microsoft.com",
            "login.live.com",
            "accounts.google.com",
            "myaccount.google.com",
            "appleid.apple.com",
            "icloud.com",
            "signin.aws.amazon.com",
            "auth0.com",
            "okta.com",
            "duo.com",
            "login.yahoo.com",
            "github.com",
            "auth.atlassian.com",
            "id.atlassian.com",
            "bitbucket.org",
            "gitlab.com"
        };

        private static readonly HashSet<string> SearchDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "google.com",
            "bing.com",
            "yahoo.com",
            "duckduckgo.com",
            "baidu.com",
            "yandex.com",
            "yandex.ru",
            "ask.com",
            "ecosia.org",
            "startpage.com",
            "qwant.com",
            "search.brave.com",
            "search.aol.com"
        };

        private static readonly HashSet<string> AdwareDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "search.conduit.com",
            "search.myway.com",
            "search.babylon.com",
            "trovi.com",
            "sweetim.com",
            "search-feed.com",
            "searchcompletion.com",
            "default-search.net",
            "istartsurf.com",
            "searchmine.net",
            "feed.sonic-search.com",
            "search.safefinder.com",
            "search.installcore.com",
            "search.ask.com",
            "search.linkeyproject.com",
            "search.hearsearch.com",
            "searchprivacy.com",
            "searchtab.net",
            "delta-search.com",
            "omiga-plus.com",
            "22find.com",
            "v9.com",
            "hao123.com"
        };

        public static bool MatchesDomain(string hostname, string catalogDomain)
        {
            if (string.IsNullOrEmpty(hostname) || string.IsNullOrEmpty(catalogDomain))
                return false;

            if (string.Equals(hostname, catalogDomain, StringComparison.OrdinalIgnoreCase))
                return true;

            // Exact subdomain boundary match without string concatenation allocation
            int prefixLen = hostname.Length - catalogDomain.Length;
            if (prefixLen > 1
                && hostname[prefixLen - 1] == '.'
                && hostname.AsSpan(prefixLen).Equals(catalogDomain.AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private static bool TryMatchCatalog(string host, HashSet<string> catalog, out string? matchedDomain)
        {
            if (!string.IsNullOrEmpty(host))
            {
                if (catalog.TryGetValue(host, out matchedDomain))
                    return true;

                int dot = host.IndexOf('.');
                while (dot >= 0 && dot + 1 < host.Length)
                {
                    string suffix = host.Substring(dot + 1);
                    if (catalog.TryGetValue(suffix, out matchedDomain))
                        return true;
                    dot = host.IndexOf('.', dot + 1);
                }
            }

            matchedDomain = null;
            return false;
        }

        public bool IsSecurityDomain(string host, out string? matchedDomain) =>
            TryMatchCatalog(host, SecurityDomains, out matchedDomain);

        public bool IsFinancialDomain(string host, out string? matchedDomain) =>
            TryMatchCatalog(host, FinancialDomains, out matchedDomain);

        public bool IsSearchDomain(string host, out string? matchedDomain) =>
            TryMatchCatalog(host, SearchDomains, out matchedDomain);

        public bool IsAdwareDomain(string host, out string? matchedDomain) =>
            TryMatchCatalog(host, AdwareDomains, out matchedDomain);
    }

    #endregion

    #region Default Implementations

    /// <summary>
    /// Production Windows implementation for hosts file system operations.
    /// </summary>
    public class WindowsHostsFileService : IHostsFileService
    {
        private static readonly string DefaultHostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        private readonly string _hostsPath;

        public WindowsHostsFileService(string? customHostsPath = null)
        {
            _hostsPath = customHostsPath ?? DefaultHostsPath;
        }

        public string GetHostsPath() => _hostsPath;

        public bool FileExists(string path) => File.Exists(path);

        public string[] ReadAllLines(string path) => File.ReadAllLines(path);

        public string ReadAllText(string path) => File.ReadAllText(path);

        public void WriteAllText(string path, string content) => File.WriteAllText(path, content, new UTF8Encoding(false));

        public void ReplaceFile(string sourceFile, string targetFile, string? backupFile) =>
            File.Replace(sourceFile, targetFile, backupFile, ignoreMetadataErrors: true);

        public void MoveFile(string sourceFile, string targetFile) => File.Move(sourceFile, targetFile);

        public void DeleteFile(string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        public FileAttributes GetAttributes(string path) => File.GetAttributes(path);

        public void SetAttributes(string path, FileAttributes attributes) => File.SetAttributes(path, attributes);

        public string? CreateSystemBackup(string sourcePath)
        {
            if (!File.Exists(sourcePath)) return null;

            string sysDir = Path.GetDirectoryName(sourcePath) ?? "";
            if (string.IsNullOrEmpty(sysDir)) return null;

            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff", CultureInfo.InvariantCulture);
            string backupPath = Path.Combine(sysDir, $"hosts.bak.{timestamp}");
            File.Copy(sourcePath, backupPath, true);
            return backupPath;
        }

        public string? CreateUserAppDataBackup(string sourcePath)
        {
            if (!File.Exists(sourcePath)) return null;

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userBackupDir = Path.Combine(localAppData, "DelgadoLogic", "LogicFlow", "Backups", "hosts");
            if (!Directory.Exists(userBackupDir))
            {
                Directory.CreateDirectory(userBackupDir);
            }

            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff", CultureInfo.InvariantCulture);
            string backupPath = Path.Combine(userBackupDir, $"hosts.bak.{timestamp}");
            File.Copy(sourcePath, backupPath, true);
            return backupPath;
        }
    }

    /// <summary>
    /// Production Windows implementation for DNS resolver cache invalidation.
    /// </summary>
    public class WindowsDnsCacheFlusher : IDnsCacheFlusher
    {
        private readonly ILogger? _logger;

        public WindowsDnsCacheFlusher(ILogger? logger = null)
        {
            _logger = logger;
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int DnsFlushResolverCache();

        public bool FlushResolverCache()
        {
            // 1. In-process Win32 P/Invoke
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    int status = DnsFlushResolverCache();
                    if (status != 0)
                    {
                        _logger?.LogDebug("Flushed DNS resolver cache via Win32 DnsFlushResolverCache.");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Win32 DnsFlushResolverCache failed; attempting ipconfig /flushdns fallback.");
            }

            // 2. Process fallback to ipconfig /flushdns
            try
            {
                using var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ipconfig.exe",
                        Arguments = "/flushdns",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };

                proc.Start();
                bool exited = proc.WaitForExit(3000);
                if (exited && proc.ExitCode == 0)
                {
                    _logger?.LogInformation("Flushed DNS resolver cache via ipconfig /flushdns.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to execute ipconfig /flushdns.");
            }

            return false;
        }

        public Task<bool> FlushResolverCacheAsync(CancellationToken ct = default)
        {
            return Task.Run(() => FlushResolverCache(), ct);
        }
    }

    /// <summary>
    /// Production multi-vector DNS adapter auditor querying WMI, .NET NetworkInterface, and the Windows Registry.
    /// </summary>
    public class WindowsDnsAdapterAuditor : IDnsAdapterAuditor
    {
        private readonly ILogger? _logger;

        public WindowsDnsAdapterAuditor(ILogger? logger = null)
        {
            _logger = logger;
        }

        public async Task<List<AdapterDnsAuditItem>> AuditAdaptersAsync(CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                var adapterMap = new Dictionary<string, AdapterDnsAuditItem>(StringComparer.OrdinalIgnoreCase);

                // ── Vector 1: .NET NetworkInterface (BCL) ──
                try
                {
                    var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                    foreach (var nic in interfaces)
                    {
                        if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                            continue;

                        string guid = NormalizeGuid(nic.Id);
                        var rawDnsList = new List<string>();

                        try
                        {
                            var ipProps = nic.GetIPProperties();
                            if (ipProps != null)
                            {
                                foreach (var dns in ipProps.DnsAddresses)
                                {
                                    rawDnsList.Add(dns.ToString());
                                }
                            }
                        }
                        catch { /* Ignore adapter property extraction issues */ }

                        var item = new AdapterDnsAuditItem
                        {
                            AdapterGuid = guid,
                            AdapterName = nic.Name,
                            Description = nic.Description,
                            InterfaceType = nic.NetworkInterfaceType.ToString(),
                            IsActive = nic.OperationalStatus == OperationalStatus.Up,
                            IsDhcpEnabled = true, // Default; overridden by WMI if available
                            DiscoverySources = new() { "NetworkInterface" },
                            DnsServers = rawDnsList.Select(DnsHostsGuardEngine.ClassifyDnsServer).ToList()
                        };

                        adapterMap[guid] = item;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed querying .NET NetworkInterface vector.");
                }

                // ── Vector 2: WMI (Win32_NetworkAdapterConfiguration) ──
                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        "SELECT SettingID, Description, ServiceName, Index, IPAddress, DNSServerSearchOrder, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True");
                    
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string settingId = obj["SettingID"]?.ToString() ?? "";
                        string guid = NormalizeGuid(settingId);
                        string desc = obj["Description"]?.ToString() ?? "Network Interface";
                        string serviceName = obj["ServiceName"]?.ToString() ?? "Adapter";
                        bool dhcp = obj["DHCPEnabled"] is bool b && b;
                        string[]? dnsServers = obj["DNSServerSearchOrder"] as string[];

                        var wmiDnsClassified = (dnsServers ?? Array.Empty<string>())
                            .Select(DnsHostsGuardEngine.ClassifyDnsServer)
                            .ToList();

                        if (adapterMap.TryGetValue(guid, out var existing))
                        {
                            existing.DiscoverySources.Add("WMI");
                            // Merge any new DNS servers found by WMI
                            foreach (var s in wmiDnsClassified)
                            {
                                if (!existing.DnsServers.Any(e => string.Equals(e.IpAddress, s.IpAddress, StringComparison.OrdinalIgnoreCase)))
                                {
                                    existing.DnsServers.Add(s);
                                }
                            }
                        }
                        else if (!string.IsNullOrEmpty(guid))
                        {
                            adapterMap[guid] = new AdapterDnsAuditItem
                            {
                                AdapterGuid = guid,
                                AdapterName = serviceName,
                                Description = desc,
                                InterfaceType = "Ethernet",
                                IsActive = true,
                                IsDhcpEnabled = dhcp,
                                DiscoverySources = new() { "WMI" },
                                DnsServers = wmiDnsClassified
                            };
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed querying WMI NetworkAdapterConfiguration vector.");
                }

                // ── Vector 3: Windows Registry (Tcpip & Tcpip6 Interfaces) ──
                try
                {
                    AuditRegistryInterfaces(adapterMap, @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces");
                    AuditRegistryInterfaces(adapterMap, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed querying Registry Tcpip Interfaces vector.");
                }

                return adapterMap.Values.ToList();
            }, ct);
        }

        private void AuditRegistryInterfaces(Dictionary<string, AdapterDnsAuditItem> adapterMap, string subKeyPath)
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var interfacesKey = baseKey.OpenSubKey(subKeyPath);
            if (interfacesKey == null) return;

            foreach (var subName in interfacesKey.GetSubKeyNames())
            {
                using var adapterKey = interfacesKey.OpenSubKey(subName);
                if (adapterKey == null) continue;

                string guid = NormalizeGuid(subName);
                string? nameServer = adapterKey.GetValue("NameServer")?.ToString();
                string? dhcpNameServer = adapterKey.GetValue("DhcpNameServer")?.ToString();
                int enableDhcp = (int)(adapterKey.GetValue("EnableDHCP") ?? 1);

                var staticServers = SplitDnsList(nameServer);
                var dhcpServers = SplitDnsList(dhcpNameServer);

                string? discrepancy = null;
                if (enableDhcp == 1 && staticServers.Count > 0 && dhcpServers.Count > 0)
                {
                    if (!staticServers.SequenceEqual(dhcpServers, StringComparer.OrdinalIgnoreCase))
                    {
                        discrepancy = $"Static registry NameServer override detected ({string.Join(", ", staticServers)}) while DHCP is active ({string.Join(", ", dhcpServers)}).";
                    }
                }

                if (adapterMap.TryGetValue(guid, out var existing))
                {
                    if (!existing.DiscoverySources.Contains("Registry"))
                    {
                        existing.DiscoverySources.Add("Registry");
                    }
                    if (!string.IsNullOrEmpty(discrepancy) && string.IsNullOrEmpty(existing.DiscrepancyWarning))
                    {
                        // Set discrepancy
                        var updated = new AdapterDnsAuditItem
                        {
                            AdapterGuid = existing.AdapterGuid,
                            AdapterName = existing.AdapterName,
                            Description = existing.Description,
                            InterfaceType = existing.InterfaceType,
                            IsActive = existing.IsActive,
                            IsDhcpEnabled = existing.IsDhcpEnabled,
                            DnsServers = existing.DnsServers,
                            DiscoverySources = existing.DiscoverySources,
                            DiscrepancyWarning = discrepancy
                        };
                        adapterMap[guid] = updated;
                    }

                    // Add any static servers from registry
                    foreach (var s in staticServers)
                    {
                        var classified = DnsHostsGuardEngine.ClassifyDnsServer(s);
                        if (!existing.DnsServers.Any(e => string.Equals(e.IpAddress, classified.IpAddress, StringComparison.OrdinalIgnoreCase)))
                        {
                            existing.DnsServers.Add(classified);
                        }
                    }
                }
            }
        }

        private static List<string> SplitDnsList(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return new List<string>();
            return raw.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                      .Select(s => s.Trim())
                      .Where(s => !string.IsNullOrEmpty(s))
                      .ToList();
        }

        private static string NormalizeGuid(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            if (Guid.TryParse(raw.Trim('{', '}'), out var parsed))
            {
                return parsed.ToString("B").ToUpperInvariant();
            }
            return raw.Trim().ToUpperInvariant();
        }
    }

    #endregion

    /// <summary>
    /// Main DNS & Hosts File Hijack Watchdog engine.
    /// </summary>
    public sealed class DnsHostsGuardEngine
    {
        private readonly ILogger<DnsHostsGuardEngine>? _logger;
        private readonly IHostsFileService _fileService;
        private readonly IDnsAdapterAuditor _adapterAuditor;
        private readonly IDnsCacheFlusher _cacheFlusher;
        private readonly IThreatDomainCatalog _threatCatalog;

        public const string Windows11DefaultHostsTemplate =
@"# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
";

        private static readonly Dictionary<string, (string ProviderName, bool SecurityFiltered)> TrustedPublicDnsMap =
            new(StringComparer.OrdinalIgnoreCase)
            {
                // Cloudflare
                ["1.1.1.1"] = ("Cloudflare Public DNS", false),
                ["1.0.0.1"] = ("Cloudflare Secondary DNS", false),
                ["1.1.1.2"] = ("Cloudflare Security (Malware Block)", true),
                ["1.0.0.2"] = ("Cloudflare Security Secondary", true),
                ["1.1.1.3"] = ("Cloudflare Family (Malware + Adult)", true),
                ["1.0.0.3"] = ("Cloudflare Family Secondary", true),
                ["2606:4700:4700::1111"] = ("Cloudflare IPv6 Primary", false),
                ["2606:4700:4700::1001"] = ("Cloudflare IPv6 Secondary", false),
                ["2606:4700:4700::1112"] = ("Cloudflare IPv6 Security", true),
                ["2606:4700:4700::1002"] = ("Cloudflare IPv6 Security Secondary", true),
                ["2606:4700:4700::1113"] = ("Cloudflare IPv6 Family", true),
                ["2606:4700:4700::1003"] = ("Cloudflare IPv6 Family Secondary", true),

                // Google
                ["8.8.8.8"] = ("Google Public DNS Primary", false),
                ["8.8.4.4"] = ("Google Public DNS Secondary", false),
                ["2001:4860:4860::8888"] = ("Google IPv6 Primary", false),
                ["2001:4860:4860::8844"] = ("Google IPv6 Secondary", false),

                // Quad9
                ["9.9.9.9"] = ("Quad9 Security Primary", true),
                ["149.112.112.112"] = ("Quad9 Security Secondary", true),
                ["9.9.9.10"] = ("Quad9 Unfiltered Primary", false),
                ["149.112.112.10"] = ("Quad9 Unfiltered Secondary", false),
                ["9.9.9.11"] = ("Quad9 ECS Primary", true),
                ["149.112.112.11"] = ("Quad9 ECS Secondary", true),
                ["2620:fe::fe"] = ("Quad9 IPv6 Primary", true),
                ["2620:fe::9"] = ("Quad9 IPv6 Secondary", true),
                ["2620:fe::fe:10"] = ("Quad9 IPv6 Unfiltered", false),
                ["2620:fe::11"] = ("Quad9 IPv6 ECS", true),

                // OpenDNS (Cisco)
                ["208.67.222.222"] = ("OpenDNS Home Primary", false),
                ["208.67.220.220"] = ("OpenDNS Home Secondary", false),
                ["208.67.222.123"] = ("OpenDNS FamilyShield Primary", true),
                ["208.67.220.123"] = ("OpenDNS FamilyShield Secondary", true),
                ["2620:119:35::35"] = ("OpenDNS IPv6 Primary", false),
                ["2620:119:53::53"] = ("OpenDNS IPv6 Secondary", false),

                // AdGuard DNS
                ["94.140.14.14"] = ("AdGuard Default Primary", true),
                ["94.140.15.15"] = ("AdGuard Default Secondary", true),
                ["94.140.14.15"] = ("AdGuard Family Primary", true),
                ["94.140.15.16"] = ("AdGuard Family Secondary", true),
                ["94.140.14.140"] = ("AdGuard Non-filtering Primary", false),
                ["94.140.14.141"] = ("AdGuard Non-filtering Secondary", false),
                ["2a10:50c0::ad1:ff"] = ("AdGuard IPv6 Primary", true),
                ["2a10:50c0::ad2:ff"] = ("AdGuard IPv6 Secondary", true),
                ["2a10:50c0::bad1:ff"] = ("AdGuard Family IPv6 Primary", true),
                ["2a10:50c0::bad2:ff"] = ("AdGuard Family IPv6 Secondary", true),

                // CleanBrowsing
                ["185.228.168.9"] = ("CleanBrowsing Security Primary", true),
                ["185.228.169.9"] = ("CleanBrowsing Security Secondary", true),
                ["185.228.168.168"] = ("CleanBrowsing Family Primary", true),
                ["185.228.169.168"] = ("CleanBrowsing Family Secondary", true),
                ["185.228.168.10"] = ("CleanBrowsing Adult Filter Primary", true),
                ["185.228.169.11"] = ("CleanBrowsing Adult Filter Secondary", true),
                ["2a0d:2a00:1::2"] = ("CleanBrowsing IPv6 Security Primary", true),
                ["2a0d:2a00:2::2"] = ("CleanBrowsing IPv6 Security Secondary", true),
                ["2a0d:2a00:1::1"] = ("CleanBrowsing IPv6 Family Primary", true),
                ["2a0d:2a00:2::1"] = ("CleanBrowsing IPv6 Family Secondary", true),

                // Control D
                ["76.76.2.0"] = ("Control D Unfiltered Primary", false),
                ["76.76.10.0"] = ("Control D Unfiltered Secondary", false),
                ["76.76.2.1"] = ("Control D Malware Filter Primary", true),
                ["76.76.10.1"] = ("Control D Malware Filter Secondary", true),
                ["76.76.2.2"] = ("Control D Ads+Malware Primary", true),
                ["76.76.10.2"] = ("Control D Ads+Malware Secondary", true),
                ["76.76.2.3"] = ("Control D Family Primary", true),
                ["76.76.10.3"] = ("Control D Family Secondary", true),
                ["2606:1a40::"] = ("Control D IPv6 Unfiltered Primary", false),
                ["2606:1a40:1::"] = ("Control D IPv6 Unfiltered Secondary", false),
                ["2606:1a40::1"] = ("Control D IPv6 Malware Primary", true),
                ["2606:1a40:1::1"] = ("Control D IPv6 Malware Secondary", true),
                ["2606:1a40::2"] = ("Control D IPv6 Ads+Malware Primary", true),
                ["2606:1a40:1::2"] = ("Control D IPv6 Ads+Malware Secondary", true)
            };

        public DnsHostsGuardEngine(ILogger<DnsHostsGuardEngine>? logger = null)
            : this(new WindowsHostsFileService(), new WindowsDnsAdapterAuditor(logger), new WindowsDnsCacheFlusher(logger), ThreatDomainCatalog.Instance, logger)
        {
        }

        public DnsHostsGuardEngine(
            IHostsFileService fileService,
            IDnsAdapterAuditor adapterAuditor,
            IDnsCacheFlusher cacheFlusher,
            ILogger<DnsHostsGuardEngine>? logger = null)
            : this(fileService, adapterAuditor, cacheFlusher, ThreatDomainCatalog.Instance, logger)
        {
        }

        public DnsHostsGuardEngine(
            IHostsFileService fileService,
            IDnsAdapterAuditor adapterAuditor,
            IDnsCacheFlusher cacheFlusher,
            IThreatDomainCatalog threatCatalog,
            ILogger<DnsHostsGuardEngine>? logger = null)
        {
            _fileService = fileService;
            _adapterAuditor = adapterAuditor;
            _cacheFlusher = cacheFlusher;
            _threatCatalog = threatCatalog;
            _logger = logger;
        }

        /// <summary>
        /// Audits both the hosts file and active network adapter DNS resolvers.
        /// </summary>
        public async Task<DnsHostsGuardReport> AuditAsync(CancellationToken ct = default)
        {
            string hostsPath = _fileService.GetHostsPath();
            bool hostsExists = _fileService.FileExists(hostsPath);

            var report = new DnsHostsGuardReport
            {
                HostsFilePath = hostsPath,
                HostsFileExists = hostsExists
            };

            // 1. Audit Hosts File
            if (hostsExists)
            {
                try
                {
                    string[] lines = _fileService.ReadAllLines(hostsPath);
                    report.TotalLinesScanned = lines.Length;

                    var parsedEntries = ParseHostsLines(lines, _threatCatalog);
                    report.TotalHostsEntries = parsedEntries.Count;
                    report.AllEntries.AddRange(parsedEntries);

                    foreach (var entry in parsedEntries)
                    {
                        if (entry.IsSuspicious)
                        {
                            report.SuspiciousEntries.Add(entry);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to read hosts file at {Path}", hostsPath);
                    report.ErrorMessage = ex.Message;
                }
            }

            // 2. Audit Adapter DNS Resolvers
            try
            {
                var resolverResult = await AuditDnsResolversAsync(ct).ConfigureAwait(false);
                
                // Populate backward-compatible NetworkAdapters list
                foreach (var adapter in resolverResult.Adapters)
                {
                    report.NetworkAdapters.Add(new AdapterDnsInfo
                    {
                        AdapterName = adapter.AdapterName,
                        Description = adapter.Description,
                        DnsServers = adapter.DnsServers.Select(s => s.IpAddress).ToList()
                    });
                }

                // Attach structured resolver audit
                typeof(DnsHostsGuardReport).GetProperty(nameof(DnsHostsGuardReport.ResolverAudit))
                    ?.SetValue(report, resolverResult);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to audit adapter DNS resolvers.");
            }

            return report;
        }

        /// <summary>
        /// Audits network adapter DNS resolvers across WMI, NetIf, and Registry.
        /// </summary>
        public async Task<DnsResolverAuditResult> AuditDnsResolversAsync(CancellationToken ct = default)
        {
            var adapters = await _adapterAuditor.AuditAdaptersAsync(ct).ConfigureAwait(false);
            return new DnsResolverAuditResult
            {
                Adapters = adapters ?? new List<AdapterDnsAuditItem>()
            };
        }

        private static readonly object _restoreSyncLock = new();

        /// <summary>
        /// Atomically restores the Windows default hosts file template with dual backup, attribute clearing, and DNS cache invalidation.
        /// </summary>
        public async Task<HostsRestoreResult> RestoreDefaultHostsFileAsync(CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                lock (_restoreSyncLock)
                {
                    string hostsPath = _fileService.GetHostsPath();
                    string? sysBackup = null;
                    string? userBackup = null;

                    int maxRetries = 15;
                    for (int attempt = 0; attempt < maxRetries; attempt++)
                    {
                        try
                        {
                            // 1. Create Dual-Path Backups
                            if (_fileService.FileExists(hostsPath))
                            {
                                sysBackup ??= _fileService.CreateSystemBackup(hostsPath);
                                userBackup ??= _fileService.CreateUserAppDataBackup(hostsPath);
                            }

                            // 2. Strip restrictive file attributes from target
                            NormalizeFileAttributes(hostsPath);

                            // 3. Atomic replace using temporary staging file
                            string etcDir = Path.GetDirectoryName(hostsPath) ?? "";
                            if (string.IsNullOrEmpty(etcDir)) etcDir = ".";

                            string tempFile = Path.Combine(etcDir, $"hosts.tmp.{Guid.NewGuid():N}");

                            try
                            {
                                _fileService.WriteAllText(tempFile, Windows11DefaultHostsTemplate);
                                NormalizeFileAttributes(tempFile);

                                if (_fileService.FileExists(hostsPath))
                                {
                                    _fileService.ReplaceFile(tempFile, hostsPath, null);
                                }
                                else
                                {
                                    _fileService.MoveFile(tempFile, hostsPath);
                                }

                                _fileService.SetAttributes(hostsPath, FileAttributes.Normal);
                            }
                            finally
                            {
                                try
                                {
                                    if (_fileService.FileExists(tempFile))
                                    {
                                        _fileService.DeleteFile(tempFile);
                                    }
                                }
                                catch { /* Best-effort temp cleanup */ }
                            }

                            // 4. Invalidate DNS Resolver Cache
                            bool cacheFlushed = _cacheFlusher.FlushResolverCache();
                            _logger?.LogInformation("Restored default clean Windows hosts file (Cache flushed: {Flushed}).", cacheFlushed);

                            return HostsRestoreResult.Ok(hostsPath, sysBackup, userBackup, cacheFlushed);
                        }
                        catch (IOException) when (attempt < maxRetries - 1)
                        {
                            Thread.Sleep(25 * (attempt + 1));
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            _logger?.LogWarning(ex, "Elevation required to restore default hosts file.");
                            return HostsRestoreResult.Fail(hostsPath, $"Elevation required: {ex.Message}", requiresElevation: true, sysBackup, userBackup);
                        }
                        catch (SecurityException ex)
                        {
                            _logger?.LogWarning(ex, "Security permissions denied when restoring hosts file.");
                            return HostsRestoreResult.Fail(hostsPath, $"Security access denied: {ex.Message}", requiresElevation: true, sysBackup, userBackup);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogError(ex, "Failed to restore default hosts file.");
                            return HostsRestoreResult.Fail(hostsPath, ex.Message, requiresElevation: false, sysBackup, userBackup);
                        }
                    }

                    return HostsRestoreResult.Fail(hostsPath, "Failed to restore hosts file due to concurrent file lock contention.", false, sysBackup, userBackup);
                }
            }, ct);
        }

        private void NormalizeFileAttributes(string filePath)
        {
            try
            {
                if (_fileService.FileExists(filePath))
                {
                    var attributes = _fileService.GetAttributes(filePath);
                    var restrictiveFlags = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System;
                    if ((attributes & restrictiveFlags) != 0)
                    {
                        _fileService.SetAttributes(filePath, FileAttributes.Normal);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Failed to normalize attributes for {Path}", filePath);
                throw;
            }
        }

        #region Parsing & Threat Intelligence Pure Logic

        /// <summary>
        /// Pure parser converting full hosts file content into analyzed HostsEntry items.
        /// </summary>
        public static List<HostsEntry> ParseHostsContent(string content, IThreatDomainCatalog? catalog = null)
        {
            if (string.IsNullOrWhiteSpace(content)) return new List<HostsEntry>();
            var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            return ParseHostsLines(lines, catalog);
        }

        /// <summary>
        /// Pure parser converting lines of hosts file into analyzed HostsEntry items.
        /// </summary>
        public static List<HostsEntry> ParseHostsLines(IEnumerable<string> lines, IThreatDomainCatalog? catalog = null)
        {
            catalog ??= ThreatDomainCatalog.Instance;
            var entries = new List<HostsEntry>();
            if (lines == null) return entries;

            int lineNumber = 0;
            foreach (var rawLine in lines)
            {
                lineNumber++;
                if (rawLine == null) continue;

                var line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;

                // Strip inline comment starting from '#'
                int hashIdx = line.IndexOf('#');
                if (hashIdx >= 0)
                {
                    line = line.Substring(0, hashIdx).Trim();
                    if (string.IsNullOrWhiteSpace(line)) continue;
                }

                var tokens = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2) continue;

                string rawIp = tokens[0].Trim();
                if (!IPAddress.TryParse(rawIp, out var parsedIp))
                {
                    // Invalid IP on line
                    continue;
                }

                bool isLoopback = rawIp == "127.0.0.1" || rawIp == "::1" || IPAddress.IsLoopback(parsedIp);
                bool isBlackhole = rawIp == "0.0.0.0" || rawIp == "::" || parsedIp.Equals(IPAddress.Any) || parsedIp.Equals(IPAddress.IPv6Any);
                bool isPrivate = IsPrivateSubnet(parsedIp);

                for (int i = 1; i < tokens.Length; i++)
                {
                    string host = tokens[i].Trim().TrimEnd('.').ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(host)) continue;

                    var entry = new HostsEntry
                    {
                        LineNumber = lineNumber,
                        IpAddress = rawIp,
                        Hostname = host,
                        IsLoopback = isLoopback,
                        IsBlackhole = isBlackhole,
                        IsPrivateIp = isPrivate
                    };

                    EvaluateHostsEntry(entry, catalog);
                    entries.Add(entry);
                }
            }

            return entries;
        }

        /// <summary>
        /// Evaluates a HostsEntry against the Threat Domain Catalog and IP destination properties.
        /// </summary>
        public static HostsEntry EvaluateHostsEntry(HostsEntry entry, IThreatDomainCatalog? catalog = null)
        {
            catalog ??= ThreatDomainCatalog.Instance;
            if (entry == null) throw new ArgumentNullException(nameof(entry));

            string host = (entry.Hostname ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            string ip = (entry.IpAddress ?? "").Trim();

            // Check if IP address is loopback / blackhole / private
            bool isLoopback = entry.IsLoopback;
            bool isBlackhole = entry.IsBlackhole;
            bool isPrivate = entry.IsPrivateIp;

            if (!isLoopback && !isBlackhole && !isPrivate && IPAddress.TryParse(ip, out var parsedIp))
            {
                isLoopback = ip == "127.0.0.1" || ip == "::1" || IPAddress.IsLoopback(parsedIp);
                isBlackhole = ip == "0.0.0.0" || ip == "::" || parsedIp.Equals(IPAddress.Any) || parsedIp.Equals(IPAddress.IPv6Any);
                isPrivate = IsPrivateSubnet(parsedIp);
                entry.IsLoopback = isLoopback;
                entry.IsBlackhole = isBlackhole;
                entry.IsPrivateIp = isPrivate;
            }

            bool isLocalSinkhole = isLoopback || isBlackhole;

            // 1. Security / AV / EDR / Microsoft Update Domains
            if (catalog.IsSecurityDomain(host, out string? matchedSec))
            {
                entry.MatchedThreatDomain = matchedSec;
                entry.IsSuspicious = true;
                entry.Severity = ThreatSeverity.Critical;

                if (isLocalSinkhole)
                {
                    entry.Category = HostsThreatCategory.SecuritySinkhole;
                    entry.Reason = $"Security/AV endpoint '{host}' sinkholed to {ip}. Blinds antivirus updates, SmartScreen, and cloud telemetry.";
                }
                else
                {
                    entry.Category = HostsThreatCategory.SecuritySpoofingRedirect;
                    entry.Reason = $"Security endpoint '{host}' redirected to external/unauthorized IP: {ip}. Potential update interception or spoofing.";
                }
                return entry;
            }

            // 2. Financial / Banking / Crypto / Identity Domains
            if (catalog.IsFinancialDomain(host, out string? matchedFin))
            {
                entry.MatchedThreatDomain = matchedFin;
                entry.IsSuspicious = true;

                if (isLocalSinkhole)
                {
                    entry.Severity = ThreatSeverity.High;
                    entry.Category = HostsThreatCategory.FinancialAccessBlock;
                    entry.Reason = $"High-value financial/identity domain '{host}' blocked or sinkholed to {ip}.";
                }
                else
                {
                    entry.Severity = ThreatSeverity.Critical;
                    entry.Category = HostsThreatCategory.FinancialPhishingRedirect;
                    entry.Reason = $"High-value banking/crypto/identity domain '{host}' redirected to external IP: {ip}. Severe credential theft/phishing threat.";
                }
                return entry;
            }

            // 3. Search Engine Domains
            if (catalog.IsSearchDomain(host, out string? matchedSearch))
            {
                entry.MatchedThreatDomain = matchedSearch;
                entry.IsSuspicious = true;

                if (isLocalSinkhole)
                {
                    entry.Severity = ThreatSeverity.Medium;
                    entry.Category = HostsThreatCategory.SearchAccessBlock;
                    entry.Reason = $"Search engine '{host}' sinkholed to {ip}.";
                }
                else
                {
                    entry.Severity = ThreatSeverity.High;
                    entry.Category = HostsThreatCategory.SearchAdwareHijack;
                    entry.Reason = $"Search engine '{host}' redirected to external IP: {ip}. Likely search query hijacking/adware injection.";
                }
                return entry;
            }

            // 4. Known Adware / Browser Hijack Distribution Targets
            if (catalog.IsAdwareDomain(host, out string? matchedAdware))
            {
                entry.MatchedThreatDomain = matchedAdware;

                if (isLocalSinkhole)
                {
                    // Benign adblocker / hosts sinkhole entry
                    entry.IsSuspicious = false;
                    entry.Severity = ThreatSeverity.Info;
                    entry.Category = HostsThreatCategory.AdwareDomainSinkholed;
                    entry.Reason = $"Known adware domain '{host}' blocked by loopback/blackhole ({ip}).";
                }
                else
                {
                    // Active adware destination
                    entry.IsSuspicious = true;
                    entry.Severity = ThreatSeverity.High;
                    entry.Category = HostsThreatCategory.AdwareDomainActive;
                    entry.Reason = $"Known adware domain '{host}' actively mapped to IP: {ip}.";
                }
                return entry;
            }

            // 5. Localhost / Standard Local Names
            if (host == "localhost" || host == "localhost.localdomain" || host == "broadcasthost" || host == "ip6-localhost" || host == "ip6-loopback")
            {
                entry.IsSuspicious = false;
                entry.Severity = ThreatSeverity.Info;
                entry.Category = HostsThreatCategory.BenignLocalMapping;
                entry.Reason = "Standard system localhost loopback mapping.";
                return entry;
            }

            // 6. Custom or Unknown Domain Mappings
            if (isLocalSinkhole || isPrivate)
            {
                entry.IsSuspicious = false;
                entry.Severity = ThreatSeverity.Info;
                entry.Category = HostsThreatCategory.CustomMapping;
                entry.Reason = $"Local/private domain mapping: {host} -> {ip}.";
            }
            else
            {
                // External public IP override
                entry.IsSuspicious = true;
                entry.Severity = ThreatSeverity.Medium;
                entry.Category = HostsThreatCategory.ExternalPublicRedirect;
                entry.Reason = $"Unlisted domain '{host}' mapped to public IP: {ip}.";
            }

            return entry;
        }

        /// <summary>
        /// Classifies a DNS server IP address against trusted public whitelists and RFC subnet boundaries.
        /// </summary>
        public static DnsServerClassification ClassifyDnsServer(string rawIp)
        {
            if (string.IsNullOrWhiteSpace(rawIp))
            {
                return new DnsServerClassification
                {
                    IpAddress = rawIp ?? "",
                    Category = DnsServerCategory.InvalidMalformed,
                    IsTrusted = false,
                    Severity = ThreatSeverity.Low,
                    WarningMessage = "Empty or missing DNS server IP address."
                };
            }

            // Strip IPv6 scope ID if present (e.g. fe80::1%12 -> fe80::1)
            string cleanIp = rawIp.Trim();
            int percentIdx = cleanIp.IndexOf('%');
            if (percentIdx > 0) cleanIp = cleanIp.Substring(0, percentIdx);

            // Strip square brackets if formatted as [2001:...]
            if (cleanIp.StartsWith("[") && cleanIp.EndsWith("]"))
            {
                cleanIp = cleanIp.Substring(1, cleanIp.Length - 2);
            }

            if (!IPAddress.TryParse(cleanIp, out var ip))
            {
                return new DnsServerClassification
                {
                    IpAddress = rawIp,
                    Category = DnsServerCategory.InvalidMalformed,
                    IsTrusted = false,
                    Severity = ThreatSeverity.Low,
                    WarningMessage = $"Malformed or invalid IP address format: '{rawIp}'."
                };
            }

            // 1. Check Trusted Public Whitelist
            string canonical = ip.ToString();
            if (TrustedPublicDnsMap.TryGetValue(canonical, out var providerInfo))
            {
                return new DnsServerClassification
                {
                    IpAddress = canonical,
                    Category = DnsServerCategory.TrustedPublic,
                    ProviderName = providerInfo.ProviderName,
                    IsTrusted = true,
                    Severity = ThreatSeverity.Info,
                    WarningMessage = null
                };
            }

            byte[] bytes = ip.GetAddressBytes();

            // 2. IPv4 Range Analysis
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                byte b0 = bytes[0];
                byte b1 = bytes[1];

                // Loopback: 127.0.0.0/8
                if (b0 == 127)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.LocalLoopback,
                        ProviderName = "Local Loopback Resolver (127.0.0.0/8)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // RFC 1918 Class A: 10.0.0.0/8
                if (b0 == 10)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.PrivateSubnet,
                        ProviderName = "Private Network (RFC 1918 10.0.0.0/8)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // RFC 1918 Class B: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
                if (b0 == 172 && b1 >= 16 && b1 <= 31)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.PrivateSubnet,
                        ProviderName = "Private Network (RFC 1918 172.16.0.0/12)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // RFC 1918 Class C: 192.168.0.0/16
                if (b0 == 192 && b1 == 168)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.PrivateSubnet,
                        ProviderName = "Local Gateway / DHCP (RFC 1918 192.168.0.0/16)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // CGNAT / Tailscale / Mesh VPN: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
                if (b0 == 100 && (b1 >= 64 && b1 <= 127))
                {
                    string name = canonical == "100.100.100.100" ? "Tailscale MagicDNS" : "CGNAT / VPN Mesh (RFC 6598 100.64.0.0/10)";
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.TailscaleCgnat,
                        ProviderName = name,
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // APIPA / Link-Local IPv4: 169.254.0.0/16
                if (b0 == 169 && b1 == 254)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.PrivateSubnet,
                        ProviderName = "APIPA Link-Local (RFC 3927 169.254.0.0/16)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }
            }
            // 3. IPv6 Range Analysis
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (IPAddress.IsLoopback(ip) || canonical == "::1")
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.LocalLoopback,
                        ProviderName = "IPv6 Loopback (::1)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // ULA: fc00::/7 (first byte is 0xFC or 0xFD)
                if ((bytes[0] & 0xFE) == 0xFC)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.PrivateSubnet,
                        ProviderName = "IPv6 Unique Local Address (ULA fc00::/7)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }

                // Link-Local: fe80::/10 (bytes[0] == 0xFE and (bytes[1] & 0xC0) == 0x80)
                if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
                {
                    return new DnsServerClassification
                    {
                        IpAddress = canonical,
                        Category = DnsServerCategory.PrivateSubnet,
                        ProviderName = "IPv6 Link-Local (fe80::/10)",
                        IsTrusted = true,
                        Severity = ThreatSeverity.Info
                    };
                }
            }

            // 4. Untrusted / Rogue Public IP Address
            return new DnsServerClassification
            {
                IpAddress = canonical,
                Category = DnsServerCategory.RogueUntrustedPublic,
                ProviderName = "Untrusted / Unknown Public DNS",
                IsTrusted = false,
                Severity = ThreatSeverity.High,
                WarningMessage = $"Untrusted public DNS resolver '{canonical}' detected. Name resolution queries may be intercepted, tracked, or redirected by third parties."
            };
        }

        /// <summary>
        /// Evaluates if an IPAddress resides in private subnets (RFC 1918, ULA, Link-Local, APIPA).
        /// </summary>
        public static bool IsPrivateSubnet(IPAddress ip)
        {
            if (ip == null) return false;

            Span<byte> b = stackalloc byte[16];
            if (!ip.TryWriteBytes(b, out int written)) return false;

            if (ip.AddressFamily == AddressFamily.InterNetwork && written >= 4)
            {
                if (b[0] == 10) return true; // 10.0.0.0/8
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12
                if (b[0] == 192 && b[1] == 168) return true; // 192.168.0.0/16
                if (b[0] == 169 && b[1] == 254) return true; // 169.254.0.0/16 (APIPA)
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true; // 100.64.0.0/10 (CGNAT)
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && written >= 16)
            {
                if ((b[0] & 0xFE) == 0xFC) return true; // ULA fc00::/7
                if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // Link-Local fe80::/10
            }

            return false;
        }

        #endregion
    }
}
