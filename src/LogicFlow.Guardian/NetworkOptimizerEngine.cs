// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – NetworkOptimizerEngine
// High-performance network & DNS optimization engine.
// Flushes DNS, resets Winsock, tunes TCP auto-tuning, and benchmarks/switches privacy DNS.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Provides network diagnostics, DNS resolver flushing, TCP stack auto-tuning, and privacy DNS switching.
/// </summary>
public sealed class NetworkOptimizerEngine
{
    private readonly ILogger<NetworkOptimizerEngine>? _logger;

    public NetworkOptimizerEngine(ILogger<NetworkOptimizerEngine>? logger = null)
    {
        _logger = logger;
    }

    // ─── Data Models ─────────────────────────────────────────────────────

    public sealed class DnsBenchmarkResult
    {
        public string ProviderName { get; init; } = "";
        public string PrimaryIp { get; init; } = "";
        public string SecondaryIp { get; init; } = "";
        public long PingLatencyMs { get; init; }
        public bool IsReachable => PingLatencyMs >= 0;
        public string LatencyFormatted => IsReachable ? $"{PingLatencyMs} ms" : "Unreachable";
    }

    public sealed class NetworkOptimizationResult
    {
        public bool DnsFlushed { get; init; }
        public bool WinsockReset { get; init; }
        public bool TcpAutoTuningApplied { get; init; }
        public List<string> Messages { get; init; } = new();
    }

    // ─── Public API ──────────────────────────────────────────────────────

    /// <summary>
    /// Flushes the Windows DNS resolver cache.
    /// </summary>
    public bool FlushDns()
    {
        _logger?.LogInformation("Flushing DNS resolver cache...");
        var (exitCode, output) = RunCommand("ipconfig.exe", "/flushdns");
        var success = exitCode == 0;
        if (success)
            _logger?.LogInformation("DNS cache successfully flushed.");
        else
            _logger?.LogWarning("DNS flush output: {Out}", output);
        return success;
    }

    /// <summary>
    /// Resets the Winsock catalog to clean network protocol state.
    /// </summary>
    public bool ResetWinsock()
    {
        _logger?.LogInformation("Resetting Winsock catalog...");
        var (exitCode, output) = RunCommand("netsh.exe", "winsock reset");
        var success = exitCode == 0;
        if (success)
            _logger?.LogInformation("Winsock catalog successfully reset.");
        else
            _logger?.LogWarning("Winsock reset output: {Out}", output);
        return success;
    }

    /// <summary>
    /// Tunes Windows TCP Window Auto-Tuning level (default: normal).
    /// </summary>
    public bool SetTcpAutoTuning(string level = "normal")
    {
        _logger?.LogInformation("Setting TCP auto-tuning level to '{Level}'...", level);
        var (exitCode, output) = RunCommand("netsh.exe", $"int tcp set global autotuninglevel={level}");
        var success = exitCode == 0;
        if (success)
            _logger?.LogInformation("TCP auto-tuning level updated.");
        else
            _logger?.LogWarning("TCP auto-tuning output: {Out}", output);
        return success;
    }

    /// <summary>
    /// Executes a full one-click network optimization (Flush DNS, Reset Winsock, Tune TCP).
    /// </summary>
    public NetworkOptimizationResult OptimizeNetwork()
    {
        _logger?.LogInformation("Starting full network optimization...");
        var messages = new List<string>();

        var dnsOk = FlushDns();
        messages.Add(dnsOk ? "DNS Cache Flushed Successfully" : "DNS Flush Failed");

        var winsockOk = ResetWinsock();
        messages.Add(winsockOk ? "Winsock Catalog Reset Successfully" : "Winsock Reset Failed");

        var tcpOk = SetTcpAutoTuning("normal");
        messages.Add(tcpOk ? "TCP Window Auto-Tuning Set to Normal" : "TCP Auto-Tuning Tuning Failed");

        return new NetworkOptimizationResult
        {
            DnsFlushed = dnsOk,
            WinsockReset = winsockOk,
            TcpAutoTuningApplied = tcpOk,
            Messages = messages
        };
    }

    /// <summary>
    /// Benchmarks response latency across major DNS providers.
    /// </summary>
    public async Task<List<DnsBenchmarkResult>> BenchmarkDnsProvidersAsync(int timeoutMs = 2000)
    {
        _logger?.LogInformation("Benchmarking DNS providers...");
        var providers = new[]
        {
            ("Cloudflare (1.1.1.1)", "1.1.1.1", "1.0.0.1"),
            ("Quad9 Privacy (9.9.9.9)", "9.9.9.9", "149.112.112.112"),
            ("Google DNS (8.8.8.8)", "8.8.8.8", "8.8.4.4"),
            ("OpenDNS (208.67.222.222)", "208.67.222.222", "208.67.220.220")
        };

        var tasks = providers.Select(async p =>
        {
            var latency = await PingHostAsync(p.Item2, timeoutMs).ConfigureAwait(false);
            return new DnsBenchmarkResult
            {
                ProviderName = p.Item1,
                PrimaryIp = p.Item2,
                SecondaryIp = p.Item3,
                PingLatencyMs = latency
            };
        });

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.OrderBy(r => r.PingLatencyMs < 0 ? long.MaxValue : r.PingLatencyMs).ToList();
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static async Task<long> PingHostAsync(string hostOrIp, int timeoutMs)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(hostOrIp, timeoutMs).ConfigureAwait(false);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : -1;
        }
        catch
        {
            return -1;
        }
    }

    private static (int exitCode, string output) RunCommand(string fileName, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return (-1, "Process start failed.");

            var sb = new StringBuilder();
            sb.AppendLine(process.StandardOutput.ReadToEnd());
            sb.AppendLine(process.StandardError.ReadToEnd());
            process.WaitForExit();

            return (process.ExitCode, sb.ToString().Trim());
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }
}
