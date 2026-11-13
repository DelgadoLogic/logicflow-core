// LogicFlow.Sentinel — Network Security Scanner (10-Vector)
// Proprietary implementation by DelgadoLogic.Tech
// Scans: open ports, ARP discovery, DNS leaks, firewall, open shares,
//        WiFi security, RDP exposure, UPnP, SMBv1, and Windows Remote Management.

using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Sentinel;

/// <summary>
/// Full 10-vector network security scanner.
/// Each scan vector runs independently and reports findings.
/// </summary>
public sealed class NetworkScanner
{
    private readonly ILogger<NetworkScanner> _logger;

    // ── Well-known risky ports ────────────────────────────────────────────────
    private static readonly (int Port, string Service, string Risk)[] RiskyPorts =
    [
        (21,    "FTP",            "Unencrypted file transfer — credentials visible on network"),
        (23,    "Telnet",         "Unencrypted remote access — critical exposure"),
        (25,    "SMTP",           "Mail relay — can be abused for spam if open"),
        (135,   "RPC",            "Remote Procedure Call — worm attack vector"),
        (139,   "NetBIOS",        "Legacy file sharing — SMBv1 worm attack vector"),
        (445,   "SMB",            "File sharing — EternalBlue / WannaCry target"),
        (1433,  "SQL Server",     "Database exposed — credential brute-force risk"),
        (1434,  "SQL Browser",    "SQL Server discovery — amplification attack vector"),
        (3306,  "MySQL",          "Database exposed — credential brute-force risk"),
        (3389,  "RDP",            "Remote Desktop — #1 ransomware entry point"),
        (5432,  "PostgreSQL",     "Database exposed — credential brute-force risk"),
        (5900,  "VNC",            "Remote desktop — often unencrypted"),
        (5985,  "WinRM HTTP",     "Windows Remote Management — lateral movement vector"),
        (5986,  "WinRM HTTPS",    "Windows Remote Management — lateral movement vector"),
        (8080,  "HTTP Proxy",     "Web proxy — potential data interception"),
        (8443,  "HTTPS Alt",      "Alternative HTTPS — may bypass security monitoring"),
    ];

    public NetworkScanner(ILogger<NetworkScanner> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Runs all 10 scan vectors and returns a consolidated report.
    /// </summary>
    public async Task<NetworkScanReport> FullScanAsync(CancellationToken ct = default)
    {
        _logger.LogInformation("[Sentinel] Starting 10-vector network security scan...");
        var report = new NetworkScanReport { ScannedAt = DateTimeOffset.UtcNow };

        // Run all vectors concurrently for speed
        var tasks = new List<Task>
        {
            Task.Run(() => report.OpenPorts = ScanOpenPorts(ct), ct),
            Task.Run(() => report.ArpDevices = DiscoverArpDevices(), ct),
            Task.Run(() => report.DnsLeakResults = CheckDnsLeaks(), ct),
            Task.Run(() => report.FirewallStatus = AuditFirewall(), ct),
            Task.Run(() => report.OpenShares = DetectOpenShares(), ct),
            Task.Run(() => report.WifiSecurity = CheckWifiSecurity(), ct),
            Task.Run(() => report.RdpExposure = CheckRdpExposure(), ct),
            Task.Run(() => report.UpnpStatus = CheckUpnp(), ct),
            Task.Run(() => report.SmbV1Status = CheckSmbV1(), ct),
            Task.Run(() => report.WinRmStatus = CheckWinRm(), ct),
        };

        await Task.WhenAll(tasks);

        report.TotalFindings = report.OpenPorts.Count + report.ArpDevices.Count
            + (report.DnsLeakResults.IsLeaking ? 1 : 0)
            + (report.FirewallStatus.IsDisabled ? 1 : 0)
            + report.OpenShares.Count
            + (report.WifiSecurity.IsVulnerable ? 1 : 0)
            + (report.RdpExposure.IsExposed ? 1 : 0)
            + (report.UpnpStatus.IsEnabled ? 1 : 0)
            + (report.SmbV1Status.IsEnabled ? 1 : 0)
            + (report.WinRmStatus.IsEnabled ? 1 : 0);

        report.RiskScore = CalculateRiskScore(report);

        _logger.LogInformation("[Sentinel] Scan complete. Risk score: {Score}/100, {Findings} findings.",
            report.RiskScore, report.TotalFindings);
        return report;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 1: Port Scanner — checks for open risky ports on localhost
    // ═══════════════════════════════════════════════════════════════════
    private List<OpenPortFinding> ScanOpenPorts(CancellationToken ct)
    {
        var findings = new List<OpenPortFinding>();
        foreach (var (port, service, risk) in RiskyPorts)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var client = new TcpClient();
                var result = client.BeginConnect(IPAddress.Loopback, port, null, null);
                bool connected = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(200));
                if (connected && client.Connected)
                {
                    findings.Add(new OpenPortFinding
                    {
                        Port = port,
                        Service = service,
                        Risk = risk,
                        Severity = port is 3389 or 445 or 23 or 139
                            ? FindingSeverity.Critical
                            : FindingSeverity.High
                    });
                    _logger.LogWarning("[Sentinel] ⚠ Open port detected: {Port} ({Service})", port, service);
                }
                client.Close();
            }
            catch { /* Port closed or filtered — safe */ }
        }
        return findings;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 2: ARP Device Discovery — finds all devices on local network
    // ═══════════════════════════════════════════════════════════════════
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physAddrLen);

    private List<ArpDevice> DiscoverArpDevices()
    {
        var devices = new List<ArpDevice>();
        try
        {
            // Get local network interfaces
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback
                    or NetworkInterfaceType.Tunnel) continue;

                var ipProps = nic.GetIPProperties();
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                    var localIp = unicast.Address;
                    var mask = unicast.IPv4Mask;

                    // Scan first 254 addresses in subnet
                    var baseBytes = localIp.GetAddressBytes();
                    var maskBytes = mask.GetAddressBytes();

                    for (int i = 1; i < 255; i++)
                    {
                        var targetBytes = new byte[4];
                        for (int j = 0; j < 4; j++)
                            targetBytes[j] = (byte)((baseBytes[j] & maskBytes[j]) | (~maskBytes[j] & (j == 3 ? i : 0)));

                        var targetIp = new IPAddress(targetBytes);
                        if (targetIp.Equals(localIp)) continue;

                        try
                        {
                            var mac = new byte[6];
                            int macLen = mac.Length;
                            int ipInt = BitConverter.ToInt32(targetBytes, 0);

                            if (SendARP(ipInt, 0, mac, ref macLen) == 0)
                            {
                                devices.Add(new ArpDevice
                                {
                                    IpAddress = targetIp.ToString(),
                                    MacAddress = string.Join(":", mac.Select(b => b.ToString("X2"))),
                                    Interface = nic.Name
                                });
                            }
                        }
                        catch { /* ARP failed for this IP — normal */ }
                    }
                }
            }

            _logger.LogInformation("[Sentinel] ARP discovery found {Count} devices on local network.", devices.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Sentinel] ARP discovery failed — may need admin privileges.");
        }
        return devices;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 3: DNS Leak Detection
    // ═══════════════════════════════════════════════════════════════════
    private DnsLeakResult CheckDnsLeaks()
    {
        var result = new DnsLeakResult();
        try
        {
            // Check which DNS servers are configured
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                var dnsServers = nic.GetIPProperties().DnsAddresses;
                foreach (var dns in dnsServers)
                {
                    result.ConfiguredDnsServers.Add(dns.ToString());

                    // Flag ISP DNS (non-privacy) servers
                    var dnsStr = dns.ToString();
                    bool isPrivacy = dnsStr is
                        "1.1.1.1" or "1.0.0.1" or                  // Cloudflare
                        "8.8.8.8" or "8.8.4.4" or                  // Google (debatable)
                        "9.9.9.9" or "149.112.112.112" or          // Quad9
                        "208.67.222.222" or "208.67.220.220" or    // OpenDNS
                        "94.140.14.14" or "94.140.15.15";          // AdGuard

                    if (!isPrivacy && !IPAddress.IsLoopback(dns)
                        && dns.AddressFamily == AddressFamily.InterNetwork)
                    {
                        result.PotentialLeaks.Add(new DnsLeak
                        {
                            Server = dnsStr,
                            Risk = "ISP or unknown DNS — queries may be logged"
                        });
                    }
                }
            }

            result.IsLeaking = result.PotentialLeaks.Count > 0;
            if (result.IsLeaking)
                _logger.LogWarning("[Sentinel] ⚠ DNS leak detected: {Count} non-privacy DNS servers.",
                    result.PotentialLeaks.Count);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] DNS leak check failed.");
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 4: Windows Firewall Audit
    // ═══════════════════════════════════════════════════════════════════
    private FirewallStatus AuditFirewall()
    {
        var status = new FirewallStatus();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile");
            if (key is not null)
            {
                var enabled = key.GetValue("EnableFirewall");
                status.StandardProfileEnabled = enabled is int val && val == 1;
            }

            using var domainKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile");
            if (domainKey is not null)
            {
                var enabled = domainKey.GetValue("EnableFirewall");
                status.DomainProfileEnabled = enabled is int val && val == 1;
            }

            using var publicKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile");
            if (publicKey is not null)
            {
                var enabled = publicKey.GetValue("EnableFirewall");
                status.PublicProfileEnabled = enabled is int val && val == 1;
            }

            status.IsDisabled = !status.StandardProfileEnabled
                             || !status.DomainProfileEnabled
                             || !status.PublicProfileEnabled;

            if (status.IsDisabled)
                _logger.LogWarning("[Sentinel] ⚠ Windows Firewall is DISABLED on one or more profiles!");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] Firewall audit failed.");
        }
        return status;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 5: Open Network Shares Detection
    // ═══════════════════════════════════════════════════════════════════
    private List<OpenShare> DetectOpenShares()
    {
        var shares = new List<OpenShare>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares");
            if (key is not null)
            {
                foreach (var shareName in key.GetValueNames())
                {
                    var data = key.GetValue(shareName) as string[];
                    if (data is null) continue;

                    var path = data.FirstOrDefault(d => d.StartsWith("Path="))?.Substring(5) ?? "";
                    var type = data.FirstOrDefault(d => d.StartsWith("Type="))?.Substring(5) ?? "";

                    // Skip administrative shares (C$, ADMIN$, IPC$)
                    if (shareName.EndsWith("$")) continue;

                    shares.Add(new OpenShare
                    {
                        Name = shareName,
                        Path = path,
                        ShareType = type,
                        Risk = "User-created share — verify access permissions"
                    });
                }
            }

            if (shares.Count > 0)
                _logger.LogWarning("[Sentinel] ⚠ {Count} open network shares detected.", shares.Count);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] Open shares detection failed.");
        }
        return shares;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 6: WiFi Security Check
    // ═══════════════════════════════════════════════════════════════════
    private WifiSecurityResult CheckWifiSecurity()
    {
        var result = new WifiSecurityResult();
        try
        {
            var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return result;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (output.Contains("State") && output.Contains("connected"))
            {
                result.IsConnected = true;

                // Extract authentication type
                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("Authentication"))
                    {
                        result.AuthType = trimmed.Split(':').Last().Trim();
                    }
                    else if (trimmed.StartsWith("Cipher"))
                    {
                        result.Cipher = trimmed.Split(':').Last().Trim();
                    }
                    else if (trimmed.StartsWith("SSID") && !trimmed.StartsWith("BSSID"))
                    {
                        result.SSID = trimmed.Split(':').Last().Trim();
                    }
                }

                // Flag weak encryption
                result.IsVulnerable = result.AuthType.Contains("Open", StringComparison.OrdinalIgnoreCase)
                    || result.AuthType.Contains("WEP", StringComparison.OrdinalIgnoreCase)
                    || result.Cipher.Contains("TKIP", StringComparison.OrdinalIgnoreCase);

                if (result.IsVulnerable)
                    _logger.LogWarning("[Sentinel] ⚠ WiFi using weak security: {Auth} / {Cipher}",
                        result.AuthType, result.Cipher);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] WiFi security check failed.");
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 7: Remote Desktop (RDP) Exposure Check
    // ═══════════════════════════════════════════════════════════════════
    private RdpExposureResult CheckRdpExposure()
    {
        var result = new RdpExposureResult();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server");
            if (key is not null)
            {
                var deny = key.GetValue("fDenyTSConnections");
                result.IsEnabled = deny is int val && val == 0;
            }

            // Check NLA (Network Level Authentication) — mitigation for brute force
            using var nlaKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            if (nlaKey is not null)
            {
                var nla = nlaKey.GetValue("UserAuthentication");
                result.NlaEnabled = nla is int val && val == 1;
            }

            result.IsExposed = result.IsEnabled && !result.NlaEnabled;

            if (result.IsExposed)
                _logger.LogWarning("[Sentinel] ⚠ RDP is enabled WITHOUT Network Level Authentication!");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] RDP exposure check failed.");
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 8: UPnP (Universal Plug and Play) Check
    // ═══════════════════════════════════════════════════════════════════
    private UpnpStatus CheckUpnp()
    {
        var status = new UpnpStatus();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SSDPSRV");
            if (key is not null)
            {
                var start = key.GetValue("Start");
                // Start type: 2 = Automatic, 3 = Manual, 4 = Disabled
                status.IsEnabled = start is int val && val <= 3;
                status.StartType = start is int s ? s : 4;
            }

            if (status.IsEnabled)
                _logger.LogWarning("[Sentinel] ⚠ UPnP (SSDP) service is active — automatic port forwarding risk.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] UPnP check failed.");
        }
        return status;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 9: SMBv1 Protocol Check (EternalBlue / WannaCry vector)
    // ═══════════════════════════════════════════════════════════════════
    private SmbV1Result CheckSmbV1()
    {
        var result = new SmbV1Result();
        try
        {
            // Check if SMBv1 is enabled via registry (Windows 8+)
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            if (key is not null)
            {
                var smb1 = key.GetValue("SMB1");
                result.IsEnabled = smb1 is null || (smb1 is int val && val != 0);
                // null means not explicitly disabled — treated as enabled
            }

            // Also check the Windows Feature state
            using var featureKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Notifications\OptionalFeatures\SMB1Protocol");
            if (featureKey is not null)
            {
                result.FeatureInstalled = true;
            }

            if (result.IsEnabled)
                _logger.LogWarning("[Sentinel] ⚠ SMBv1 is ENABLED — critical WannaCry/EternalBlue attack vector!");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] SMBv1 check failed.");
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    // VECTOR 10: Windows Remote Management (WinRM) Check
    // ═══════════════════════════════════════════════════════════════════
    private WinRmResult CheckWinRm()
    {
        var result = new WinRmResult();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service");
            if (key is not null)
            {
                var allow = key.GetValue("allow_remote_requests");
                result.IsEnabled = allow is int val && val == 1;
            }

            // Check HTTP listener
            using var listenerKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTP");
            result.HttpListenerActive = listenerKey is not null;

            if (result.IsEnabled)
                _logger.LogWarning("[Sentinel] ⚠ WinRM is accepting remote requests — lateral movement risk.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] WinRM check failed.");
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    // Risk Score Calculator (0-100, higher = worse)
    // ═══════════════════════════════════════════════════════════════════
    private static int CalculateRiskScore(NetworkScanReport report)
    {
        int score = 0;

        // Open ports: critical ports = 15 pts each, high = 8 pts each
        score += report.OpenPorts.Count(p => p.Severity == FindingSeverity.Critical) * 15;
        score += report.OpenPorts.Count(p => p.Severity == FindingSeverity.High) * 8;

        // DNS leaks: 10 pts
        if (report.DnsLeakResults.IsLeaking) score += 10;

        // Firewall disabled: 20 pts (critical)
        if (report.FirewallStatus.IsDisabled) score += 20;

        // Open shares: 5 pts each
        score += report.OpenShares.Count * 5;

        // Weak WiFi: 15 pts
        if (report.WifiSecurity.IsVulnerable) score += 15;

        // RDP exposed without NLA: 20 pts (critical)
        if (report.RdpExposure.IsExposed) score += 20;

        // UPnP active: 8 pts
        if (report.UpnpStatus.IsEnabled) score += 8;

        // SMBv1 enabled: 20 pts (critical — WannaCry vector)
        if (report.SmbV1Status.IsEnabled) score += 20;

        // WinRM enabled: 12 pts
        if (report.WinRmStatus.IsEnabled) score += 12;

        return Math.Min(100, score);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Data Models — Network Scan Report
// ═══════════════════════════════════════════════════════════════════════

public sealed class NetworkScanReport
{
    public DateTimeOffset ScannedAt { get; set; }
    public int RiskScore { get; set; }
    public int TotalFindings { get; set; }

    // Vector results
    public List<OpenPortFinding> OpenPorts { get; set; } = [];
    public List<ArpDevice> ArpDevices { get; set; } = [];
    public DnsLeakResult DnsLeakResults { get; set; } = new();
    public FirewallStatus FirewallStatus { get; set; } = new();
    public List<OpenShare> OpenShares { get; set; } = [];
    public WifiSecurityResult WifiSecurity { get; set; } = new();
    public RdpExposureResult RdpExposure { get; set; } = new();
    public UpnpStatus UpnpStatus { get; set; } = new();
    public SmbV1Result SmbV1Status { get; set; } = new();
    public WinRmResult WinRmStatus { get; set; } = new();
}

public enum FindingSeverity { Info, Low, Medium, High, Critical }

public sealed record OpenPortFinding
{
    public int Port { get; init; }
    public string Service { get; init; } = "";
    public string Risk { get; init; } = "";
    public FindingSeverity Severity { get; init; }
}

public sealed record ArpDevice
{
    public string IpAddress { get; init; } = "";
    public string MacAddress { get; init; } = "";
    public string Interface { get; init; } = "";
}

public sealed class DnsLeakResult
{
    public bool IsLeaking { get; set; }
    public List<string> ConfiguredDnsServers { get; set; } = [];
    public List<DnsLeak> PotentialLeaks { get; set; } = [];
}

public sealed record DnsLeak
{
    public string Server { get; init; } = "";
    public string Risk { get; init; } = "";
}

public sealed class FirewallStatus
{
    public bool StandardProfileEnabled { get; set; }
    public bool DomainProfileEnabled { get; set; }
    public bool PublicProfileEnabled { get; set; }
    public bool IsDisabled { get; set; }
}

public sealed record OpenShare
{
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public string ShareType { get; init; } = "";
    public string Risk { get; init; } = "";
}

public sealed class WifiSecurityResult
{
    public bool IsConnected { get; set; }
    public string SSID { get; set; } = "";
    public string AuthType { get; set; } = "";
    public string Cipher { get; set; } = "";
    public bool IsVulnerable { get; set; }
}

public sealed class RdpExposureResult
{
    public bool IsEnabled { get; set; }
    public bool NlaEnabled { get; set; }
    public bool IsExposed { get; set; }
}

public sealed class UpnpStatus
{
    public bool IsEnabled { get; set; }
    public int StartType { get; set; } = 4;
}

public sealed class SmbV1Result
{
    public bool IsEnabled { get; set; }
    public bool FeatureInstalled { get; set; }
}

public sealed class WinRmResult
{
    public bool IsEnabled { get; set; }
    public bool HttpListenerActive { get; set; }
}
