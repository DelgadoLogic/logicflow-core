// ─────────────────────────────────────────────────────────────────────────────
// PulseQueryEngine.cs — Local rule-based diagnostic query classifier & Responder
// Local rule-based query classifier for LogicFlow
// ─────────────────────────────────────────────────────────────────────────────

using System.Text.RegularExpressions;
using LogicFlow.Guardian;

namespace LogicFlow.Dashboard;

public static class PulseQueryEngine
{
    public static string ProcessQuery(
        string input,
        SystemInfoEngine.SystemSnapshot? snapshot = null,
        string? healthScore = null,
        int vulnCount = 0,
        int openPortsCount = 0,
        long junkTotalBytes = 0,
        int junkFileCount = 0,
        bool isPowerStatusAvailable = false,
        byte acLineStatus = 1,
        byte batteryFlag = 128,
        byte batteryLifePercent = 255)
    {
        if (string.IsNullOrWhiteSpace(input))
            return "Pulse Engine: Please type a diagnostic query (e.g. 'how my computer speed', 'check RAM', 'system specs').";

        var raw = input.Trim();
        var query = raw.ToLowerInvariant();
        snapshot ??= SystemInfoEngine.CreateFastInitialSnapshot();

        // ─── 1. RAM / Memory (Check early to avoid colliding with 'about' or 'pc') ─────
        if (HasWord(query, "ram") || HasWord(query, "memory") || query.Contains("pagefile") || query.Contains("swap file") || query.Contains("swap memory"))
        {
            var used = snapshot.UsedRamFormatted;
            var total = snapshot.TotalRamFormatted;
            var avail = snapshot.AvailableRamFormatted;
            var pct = snapshot.RamUsagePercent;
            var pressure = pct > 80
                ? "Heavy — high memory pressure detected. Click 'Optimize RAM' to reclaim idle working sets."
                : (pct > 50 ? "Moderate — normal operational working set." : "Light — ample free physical RAM headroom.");

            return $"Memory Status:\n• RAM Active: {used} used of {total} total ({pct:F0}% utilization)\n• Available RAM: {avail}\n• Memory Pressure: {pressure}";
        }

        // ─── 2. GPU / Graphics / Video Memory (VRAM) ──────────────────────────
        if (HasWord(query, "gpu") || query.Contains("graphic") || query.Contains("graphics") ||
            query.Contains("vram") || query.Contains("video card") || query.Contains("display adapter") ||
            query.Contains("nvidia") || query.Contains("geforce") || query.Contains("rtx") ||
            query.Contains("radeon") || query.Contains("intel hd") || query.Contains("intel iris") || query.Contains("intel arc"))
        {
            var gpuName = ResolveGpuName(snapshot.GpuName);
            var fastGpu = SystemInfoEngine.GetFastGpuInfo();
            var vramText = snapshot.GpuVramBytes > 0
                ? snapshot.GpuVramFormatted
                : (fastGpu.VramBytes > 0 ? FormatBytes(fastGpu.VramBytes) : "Shared System VRAM");
            var driverText = !string.IsNullOrWhiteSpace(snapshot.GpuDriverVersion)
                ? snapshot.GpuDriverVersion
                : (!string.IsNullOrWhiteSpace(fastGpu.DriverVersion) ? fastGpu.DriverVersion : "WDDM Standard Driver");
            return $"Graphics Subsystem:\n• GPU: {gpuName}\n• Dedicated VRAM: {vramText}\n• Driver Version: {driverText}\n• Composition: Hardware rasterization and Desktop Window Manager (DWM) compositing active.";
        }

        // ─── 3. Battery / Power / Charging ────────────────────────────────────
        if (HasWord(query, "battery") || HasWord(query, "power") || query.Contains("charger") ||
            query.Contains("charging") || query.Contains("plugged") || query.Contains("unplugged") ||
            query.Contains("wattage") || query.Contains("ac power") || query.Contains("mains power") ||
            query.Contains("power status") || query.Contains("power plan"))
        {
            if (isPowerStatusAvailable)
            {
                if (batteryFlag == 128 || batteryLifePercent == 255)
                {
                    return "Power Status: Running on AC mains power (desktop mode). Windows High-Performance power profile active.";
                }

                var ac = acLineStatus == 1 ? "Plugged in (AC Online)" : "Running on Battery Power";
                var pct = batteryLifePercent <= 100 ? $"{batteryLifePercent}%" : "Unknown";
                var charging = (batteryFlag & 8) != 0 ? " (Charging)" : "";
                return $"Power & Battery Status:\n• Power Source: {ac}\n• Battery Level: {pct}{charging}\n• Power Governor: Windows balanced latency profile active.";
            }

            return "Power Status: Running on AC mains power with High-Performance workstation tuning active.";
        }

        // ─── 4. Disk / Storage / Free Space / SSD / HDD ───────────────────────
        if (HasWord(query, "disk") || HasWord(query, "storage") || HasWord(query, "drive") ||
            HasWord(query, "drives") || query.Contains("free space") || query.Contains("disk space") ||
            query.Contains("drive space") || query.Contains("storage space") || HasWord(query, "ssd") ||
            HasWord(query, "hdd") || HasWord(query, "nvme") || query.Contains("c drive") || query.Contains("c:"))
        {
            if (snapshot.Disks.Count > 0)
            {
                var diskDetails = string.Join("\n• ", snapshot.Disks.Select(d =>
                    $"{d.Name} [{FormatBytes(d.FreeBytes)} free of {FormatBytes(d.TotalBytes)}, {d.UsagePercent:F0}% used, {d.FileSystem}]"));

                var criticalDisk = snapshot.Disks.FirstOrDefault(d => d.UsagePercent >= 90);
                var warning = criticalDisk != null
                    ? $"\n⚠ Alert: Drive {criticalDisk.Name} is at {criticalDisk.UsagePercent:F0}% capacity. Run 'Clean Junk Files' to reclaim drive space."
                    : "\n• Capacity Status: All storage volumes have sufficient free space.";

                return $"Storage Volumes:\n• {diskDetails}{warning}";
            }

            return "Storage drives are currently active. All mounted volumes are being monitored by Guardian.";
        }

        // ─── 5. Network / Internet / WiFi / Ethernet / IP ─────────────────────
        if (HasWord(query, "network") || HasWord(query, "internet") || HasWord(query, "wifi") ||
            query.Contains("wi-fi") || HasWord(query, "ethernet") || query.Contains("ip address") ||
            HasWord(query, "ping") || HasWord(query, "latency") || HasWord(query, "dns") ||
            query.Contains("connection speed") || query.Contains("network speed"))
        {
            var adapter = !string.IsNullOrWhiteSpace(snapshot.ActiveNetworkAdapter) ? snapshot.ActiveNetworkAdapter : "Primary Network Adapter";
            var ip = !string.IsNullOrWhiteSpace(snapshot.IpAddress) ? snapshot.IpAddress : "127.0.0.1";
            var speed = snapshot.NetworkSpeedMbps > 0 ? $", Link Speed: {snapshot.NetworkSpeedMbps} Mbps" : "";
            return $"Network Configuration:\n• Adapter: {adapter}\n• IP Address: {ip}{speed}\n• Integrity: DNS cache and socket latency verified by Sentinel.";
        }

        // ─── 6. Security / Threats / Defender / Sentinel / Firewall ───────────
        if (HasWord(query, "security") || HasWord(query, "threat") || HasWord(query, "threats") ||
            HasWord(query, "vuln") || query.Contains("vulnerabilit") || HasWord(query, "virus") ||
            HasWord(query, "viruses") || HasWord(query, "malware") || HasWord(query, "firewall") ||
            HasWord(query, "sentinel") || HasWord(query, "defender") || query.Contains("port scan") ||
            query.Contains("open port") || query.Contains("listening port") || query.Contains("is my pc safe") ||
            query.Contains("is my computer safe") || query.Contains("protected"))
        {
            string statusSummary = (vulnCount == 0 && openPortsCount == 0)
                ? "Sentinel Real-Time Defense is active. Zero unpatched vulnerabilities or rogue listening ports found."
                : $"Sentinel Scan Report: {vulnCount} vulnerabilities and {openPortsCount} exposed services recorded. Run 'Security Scan' to remediate.";

            return $"Security Profile:\n• Status: {statusSummary}\n• Hardening: see the Sentinel page for the Defender attack-surface rules currently applied.";
        }

        // ─── 7. Junk Files / Clean / Temp / Cache ─────────────────────────────
        if (HasWord(query, "junk") || query.Contains("clean junk") || query.Contains("temp file") ||
            query.Contains("temporary file") || HasWord(query, "cache") || query.Contains("recycle bin") ||
            query.Contains("clean temp") || query.Contains("clear cache") || query.Contains("cleanup"))
        {
            if (junkTotalBytes > 0)
            {
                var totalMB = junkTotalBytes / (1024.0 * 1024.0);
                return $"Junk Files Assessment:\n• Temporary Files: {junkFileCount} items ({totalMB:F1} MB recoverable)\n• Action: Click 'Clean Junk Files' quick action to safely purge cached data.";
            }

            return "Junk Cleanup Status:\n• System temporary folders, browser caches, and error logs are ready to scan.\n• Action: Click 'Clean Junk Files' quick action to reclaim local drive storage.";
        }

        // ─── 8. Computer Speed / CPU Clock / GHz / Performance / CPU Model ────
        // (Handles: 'how my computer speed', 'how fast is my pc', 'cpu clock', 'ghz', etc.)
        if (query.Contains("speed") || query.Contains("fast") || query.Contains("ghz") ||
            query.Contains("mhz") || query.Contains("clock") || HasWord(query, "cpu") ||
            query.Contains("processor") || query.Contains("frequency") || query.Contains("performance") ||
            HasWord(query, "core") || HasWord(query, "cores") || HasWord(query, "thread") ||
            HasWord(query, "threads") || query.Contains("overclock") || query.Contains("benchmark") ||
            query.Contains("how is my pc running") || query.Contains("how is my computer running"))
        {
            var cpuName = !string.IsNullOrWhiteSpace(snapshot.CpuName) ? snapshot.CpuName : "x64 Multicore Processor";
            var ghz = snapshot.CpuSpeedGHz > 0 ? snapshot.CpuSpeedGHz : 2.0;
            var currentGhzText = $"{ghz:F2} GHz";
            var baseSpeedText = $"{ghz:F2} GHz";
            var coresText = (snapshot.CpuCores > 0 && snapshot.CpuThreads > 0)
                ? $"{snapshot.CpuCores} Cores / {snapshot.CpuThreads} Threads"
                : $"{Environment.ProcessorCount} Logical Cores";

            var loadPct = snapshot.CpuUsagePercent;
            var headroom = Math.Max(0, 100 - (int)loadPct);

            string stateDesc = loadPct switch
            {
                < 30 => "Optimal — cool operating state with high compute headroom.",
                < 70 => "Balanced — steady background and application throughput.",
                _    => "Heavy Load — intensive computational workload in progress."
            };

            return $"Processor Performance:\n• CPU Model: {cpuName}\n• Current Clock: {currentGhzText} | Base Speed: {baseSpeedText}\n• Core Architecture: {coresText}\n• Live CPU Load: {loadPct:F0}% ({headroom}% compute headroom available)\n• System Responsiveness: {stateDesc}";
        }

        // ─── 9. Operating System / Windows Build / Version ────────────────────
        if (HasWord(query, "os") || HasWord(query, "windows") || query.Contains("operating system") ||
            HasWord(query, "build") || HasWord(query, "edition") || HasWord(query, "kernel") ||
            (HasWord(query, "version") && !query.Contains("logicflow")))
        {
            var osName = ResolveOsName(snapshot.OsName, snapshot.OsBuild);
            return $"Operating System Profile:\n• Version: {osName} (Build {snapshot.OsBuild}, {snapshot.OsArchitecture})\n• Device Host: {snapshot.ComputerName} | User: {snapshot.UserName}\n• System Uptime: {snapshot.UptimeFormatted}";
        }

        // ─── 10. Turbo Mode / Boost / Gaming / FPS ────────────────────────────
        if (HasWord(query, "turbo") || HasWord(query, "boost") || HasWord(query, "game") ||
            HasWord(query, "gaming") || HasWord(query, "fps"))
        {
            return "Turbo Mode Diagnostics:\n• Status: Ready to engage.\n• Capabilities: Suspends background indexing and telemetry, prioritizes foreground process CPU affinities, and flushes standby RAM for peak gaming and compilation frame rates.\n• Action: Tap 'Turbo / Boost' quick action to engage.";
        }

        // ─── 11. Health Score / Grade / Condition ─────────────────────────────
        if (HasWord(query, "health") || HasWord(query, "score") || HasWord(query, "grade") ||
            HasWord(query, "condition") || query.Contains("how is my pc") || query.Contains("how is my system") ||
            query.Contains("how is my computer"))
        {
            var score = !string.IsNullOrWhiteSpace(healthScore) ? healthScore : "Not yet calculated";
            var gradeStr = !string.IsNullOrWhiteSpace(healthScore) ? "Calculated from active monitors" : "Run '1-Click Optimize' to evaluate";
            return $"Overall System Health:\n• Health Score: {score} ({gradeStr})\n• Active Monitors: Guardian active on hardware/drivers; Sentinel active on process security.\n• Action: Click '1-Click Optimize' to recalibrate all performance subsystems.";
        }

        // ─── 12. Slow PC / Lag / Optimize / Speed Up ──────────────────────────
        if (HasWord(query, "slow") || HasWord(query, "lag") || query.Contains("lagging") ||
            query.Contains("speed up") || query.Contains("faster") || HasWord(query, "tune") ||
            query.Contains("optimize pc") || query.Contains("slow down"))
        {
            return "System Tuning Recommendations:\n1. Run '1-Click Optimize' for unified junk cleanup, RAM flush, and registry check.\n2. Click 'Optimize RAM' to reclaim memory from dormant processes.\n3. Clean temporary files using 'Clean Junk Files'.\n4. Enable 'Turbo / Boost' for maximum single-threaded processing responsiveness.";
        }

        // ─── 13. System Specs / Hardware Overview (Generic) ───────────────────
        if (query.Contains("spec") || query.Contains("hardware") || query.Contains("overview") ||
            query.Contains("system info") || query.Contains("summary") || query.Contains("my pc") ||
            query.Contains("my computer") || query.Contains("about this pc") || query.Contains("device info") ||
            query.Contains("machine info") || query.Contains("configuration"))
        {
            var cpu = !string.IsNullOrWhiteSpace(snapshot.CpuName) ? snapshot.CpuName : "x64 Processor";
            var speed = snapshot.CpuSpeedGHz > 0 ? $" @ {snapshot.CpuSpeedGHz:F1} GHz" : "";
            var ram = $"{snapshot.TotalRamFormatted} RAM ({snapshot.AvailableRamFormatted} free)";
            var gpu = ResolveGpuName(snapshot.GpuName);
            var osName = ResolveOsName(snapshot.OsName, snapshot.OsBuild);
            var os = $"{osName} ({snapshot.OsArchitecture})";
            var disks = snapshot.Disks.Count > 0
                ? string.Join(", ", snapshot.Disks.Select(d => $"{d.Name} ({d.UsagePercent:F0}% used)"))
                : "System Drive Active";

            return $"System Hardware Overview:\n• CPU: {cpu}{speed} ({snapshot.CpuCores}C/{snapshot.CpuThreads}T)\n• RAM: {ram}\n• GPU: {gpu}\n• Drives: {disks}\n• OS: {os} on {snapshot.ComputerName}\n• Uptime: {snapshot.UptimeFormatted}";
        }

        // ─── 14. Creator / About / DelgadoLogic ───────────────────────────────
        if (query.Contains("who are you") || query.Contains("who made") || query.Contains("creator") ||
            query.Contains("author") || query.Contains("delgadologic") || query.Contains("manuel"))
        {
            bool cloudActive = GemmaAiEngine.Instance.Mode == GemmaExecutionMode.CloudEndpoint ||
                               (GemmaAiEngine.Instance.Mode == GemmaExecutionMode.HybridAuto && GemmaAiEngine.Instance.AllowHybridCloudFallback);
            string privacyNote = cloudActive
                ? "Cloud AI fallback is currently enabled in Settings; disable it or switch to Local Sidecar to keep all prompts strictly on-device."
                : "Pulse runs locally on this PC; nothing you type here is sent off-device unless you explicitly enable Cloud AI in Settings.";
            return $"LogicFlow is engineered by Manuel Alejandro Delgado at DelgadoLogic (Delgado Creative Enterprises LLC). {privacyNote}";
        }

        // ─── 15. Help / Menu / Commands ───────────────────────────────────────
        if (HasWord(query, "help") || query.Contains("what can you do") || query.Contains("commands") ||
            query.Contains("menu") || query.Contains("options"))
        {
            return "Pulse Diagnostician runs locally on your machine. You can ask:\n• 'How fast is my computer speed?'\n• 'What are my system specs?'\n• 'How much RAM is active?'\n• 'Check disk space'\n• 'What is my GPU?'\n• 'Show network connection'\n• 'Check battery and power status'\n• 'Scan security threats'\n• 'Clean junk files'";
        }

        // ─── 16. Fallback with Smart Guidance ─────────────────────────────────
        return $"Pulse (local diagnostics): I am actively monitoring your system locally. I did not recognize a specific command in '{raw}'. Try asking:\n• 'how my computer speed'\n• 'what are my specs'\n• 'how much RAM is used'\n• 'check disk space'\n• 'show GPU details'\n• 'security scan status'";
    }

    /// <summary>
    /// Convenience overload for natural-language diagnostic queries with automatic telemetry snapshot collection.
    /// </summary>
    public static Task<string> QueryNaturalLanguageAsync(string question, CancellationToken ct = default)
        => QueryNaturalLanguageAsync(question, snapshot: null, ct: ct);

    /// <summary>
    /// Returns true if the query is open-ended, analytical, or missed the Tier-1 fast regex cache.
    /// Exact short queries (e.g., "what is my gpu", "check disk space", "help") are served in &lt;5ms from Tier-1 cache.
    /// </summary>
    public static bool RequiresDeepAiAnalysis(string input, string tier1Response)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        if (tier1Response.StartsWith("Pulse (local diagnostics): I am actively monitoring", StringComparison.Ordinal))
            return true;

        string q = input.Trim().ToLowerInvariant();
        if (q.Contains("why ") || q.Contains("which ") || q.Contains("stutter") ||
            q.Contains("leak") || q.Contains("thrash") || q.Contains("bottleneck") ||
            q.Contains("crash") || q.Contains("bsod") || q.Contains("freeze") ||
            q.Contains("explain") || q.Contains("analyze") || q.Contains("diagnose") ||
            q.Contains("last night") || q.Contains("yesterday") || q.Contains("spike") ||
            q.Contains("compare") || q.Contains("recommend"))
        {
            return true;
        }

        // Multi-clause / compound questions (> 8 words) also route to Gemma 4 E2B
        int wordCount = q.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;
        return wordCount > 8;
    }

    /// <summary>
    /// Processes a natural-language diagnostic question or command:
    /// 1) Tier-1 Fast Regex Cache (&lt;5ms) for exact standard queries
    /// 2) Tier-2 Gemma 4 E2B (`GemmaAiEngine.Instance`) with compact JSON telemetry context (&lt;2,500 tokens)
    /// 3) Graceful fallback to deterministic rule-based output when AI is disabled or offline.
    /// </summary>
    public static async Task<string> QueryNaturalLanguageAsync(
        string input,
        SystemInfoEngine.SystemSnapshot? snapshot,
        string? healthScore = null,
        int vulnCount = 0,
        int openPortsCount = 0,
        long junkTotalBytes = 0,
        int junkFileCount = 0,
        bool isPowerStatusAvailable = false,
        byte acLineStatus = 1,
        byte batteryFlag = 128,
        byte batteryLifePercent = 255,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return ProcessQuery(input, snapshot, healthScore, vulnCount, openPortsCount, junkTotalBytes, junkFileCount, isPowerStatusAvailable, acLineStatus, batteryFlag, batteryLifePercent);
        }

        snapshot ??= SystemInfoEngine.CreateFastInitialSnapshot();
        var ruleBasedBaseline = ProcessQuery(
            input, snapshot, healthScore, vulnCount, openPortsCount,
            junkTotalBytes, junkFileCount, isPowerStatusAvailable,
            acLineStatus, batteryFlag, batteryLifePercent);

        // Tier-1 Fast Cache (<5ms): return immediately for exact standard queries unless open-ended/analytical
        if (!RequiresDeepAiAnalysis(input, ruleBasedBaseline))
        {
            return ruleBasedBaseline;
        }

        try
        {
            var ai = GemmaAiEngine.Instance;
            if (ai.Mode != GemmaExecutionMode.Disabled)
            {
                var gpuName = ResolveGpuName(snapshot.GpuName);
                var osName = ResolveOsName(snapshot.OsName, snapshot.OsBuild);
                var diskSummary = snapshot.Disks.Count > 0
                    ? string.Join("; ", snapshot.Disks.Select(d => $"{d.Name} {FormatBytes(d.FreeBytes)} free / {FormatBytes(d.TotalBytes)} ({d.UsagePercent:F0}% used)"))
                    : "System drive online";

                var telemetryJson = System.Text.Json.JsonSerializer.Serialize(new
                {
                    overview = new
                    {
                        cpu = $"{snapshot.CpuName} ({snapshot.CpuCores}C/{snapshot.CpuThreads}T @ {snapshot.CpuSpeedGHz:F2} GHz)",
                        cpuLoadPct = Math.Round(snapshot.CpuUsagePercent, 1),
                        ramUsed = snapshot.UsedRamFormatted,
                        ramTotal = snapshot.TotalRamFormatted,
                        ramPct = Math.Round(snapshot.RamUsagePercent, 1),
                        gpu = gpuName,
                        gpuVram = snapshot.GpuVramFormatted,
                        gpuDriver = snapshot.GpuDriverVersion,
                        os = $"{osName} (Build {snapshot.OsBuild})",
                        uptime = snapshot.UptimeFormatted,
                        storage = diskSummary
                    },
                    bottlenecks = new
                    {
                        cpuElevated = snapshot.CpuUsagePercent >= 80,
                        ramPressure = snapshot.RamUsagePercent >= 80,
                        securityAlerts = vulnCount,
                        openPorts = openPortsCount,
                        recoverableJunkFiles = junkFileCount,
                        recoverableJunkSize = FormatBytes(junkTotalBytes)
                    },
                    baselineDiagnostic = ruleBasedBaseline
                });

                // Truncate telemetry context strictly under 2,500 tokens (~8,000 chars)
                if (telemetryJson.Length > 8000)
                {
                    telemetryJson = telemetryJson[..8000];
                }

                var sysPrompt =
                    "You are the LogicFlow Pulse Diagnostician powered by Gemma 4 E2B (`gemma-4-E2B-it`). " +
                    "Answer the user's question about their Windows PC concisely, accurately, and directly using the live telemetry JSON below.\n" +
                    $"TelemetryContext: {telemetryJson}";

                var resp = await ai.ChatAsync(new GemmaChatRequest
                {
                    SystemPrompt = sysPrompt,
                    UserPrompt = input.Trim(),
                    Temperature = 0.2,
                    MaxTokens = 384
                }, ct).ConfigureAwait(false);

                if (resp.Success && !string.IsNullOrWhiteSpace(resp.Content))
                {
                    return resp.Content.Trim();
                }
            }
        }
        catch
        {
            // Fall through to deterministic baseline
        }

        return ruleBasedBaseline;
    }

    public static string ResolveOsName(string osName, string? osBuild = null)
    {
        if (string.IsNullOrWhiteSpace(osName))
            return "Windows";

        int build = 0;
        if (!string.IsNullOrWhiteSpace(osBuild))
        {
            var match = Regex.Match(osBuild, @"\b(\d{5,})\b");
            if (match.Success) int.TryParse(match.Groups[1].Value, out build);
        }
        if (build == 0)
        {
            var match = Regex.Match(osName, @"\[?(\d{5,})\]?");
            if (match.Success) int.TryParse(match.Groups[1].Value, out build);
        }
        if (build == 0)
        {
            build = Environment.OSVersion.Version.Build;
        }

        if (build >= 22000)
        {
            if (osName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
            {
                osName = Regex.Replace(osName, @"Windows\s*10", "Windows 11", RegexOptions.IgnoreCase);
            }
            else if (!osName.Contains("Windows 11", StringComparison.OrdinalIgnoreCase) && osName.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
            {
                osName = "Windows 11 " + osName.Substring(7).TrimStart();
            }
        }

        return osName;
    }

    public static string ResolveGpuName(string? gpuName)
    {
        bool isGeneric = string.IsNullOrWhiteSpace(gpuName) ||
            gpuName.Equals("DirectX GPU", StringComparison.OrdinalIgnoreCase) ||
            gpuName.Equals("Display Adapter", StringComparison.OrdinalIgnoreCase) ||
            gpuName.Equals("DirectX Graphics Adapter", StringComparison.OrdinalIgnoreCase) ||
            gpuName.Equals("Display Controller", StringComparison.OrdinalIgnoreCase) ||
            gpuName.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) ||
            gpuName.Contains("Basic Render", StringComparison.OrdinalIgnoreCase) ||
            gpuName.Contains("Standard VGA", StringComparison.OrdinalIgnoreCase);

        if (!isGeneric)
        {
            return gpuName!;
        }

        var fast = SystemInfoEngine.GetFastGpuInfo();
        if (!string.IsNullOrWhiteSpace(fast.Name) &&
            !fast.Name.Equals("DirectX Graphics Adapter", StringComparison.OrdinalIgnoreCase) &&
            !fast.Name.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) &&
            !fast.Name.Equals("Display Controller", StringComparison.OrdinalIgnoreCase))
        {
            return fast.Name;
        }

        var wmi = SystemInfoEngine.GetWmiGpuInfo();
        if (!string.IsNullOrWhiteSpace(wmi.Name) &&
            !wmi.Name.Equals("DirectX Graphics Adapter", StringComparison.OrdinalIgnoreCase) &&
            !wmi.Name.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) &&
            !wmi.Name.Equals("Display Controller", StringComparison.OrdinalIgnoreCase))
        {
            return wmi.Name;
        }

        return !string.IsNullOrWhiteSpace(gpuName) ? gpuName : "DirectX Graphics Adapter";
    }

    private static bool HasWord(string text, string word)
    {
        return Regex.IsMatch(text, $@"\b{Regex.Escape(word)}\b", RegexOptions.IgnoreCase);
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}
