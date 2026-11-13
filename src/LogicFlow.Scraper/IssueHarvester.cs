// LogicFlow.Scraper — Research Issue Harvester
// Proprietary implementation by DelgadoLogic.Tech
// Gathers Windows issue intelligence from public forums and support pages

using System.Text.Json;
using System.Text.Json.Serialization;
using HtmlAgilityPack;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Scraper;

/// <summary>
/// Scrapes Windows-related issue reports from public forums, Microsoft support,
/// and community pages. Outputs structured JSON for LogicFlow's self-evolving intelligence.
/// </summary>
public sealed class IssueHarvester : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<IssueHarvester> _logger;
    private readonly string _outputDirectory;

    private static readonly string[] TargetUrls =
    [
        "https://support.microsoft.com/en-us/topic/windows-11-known-issues",
        "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2",
        "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-25h2",
    ];

    public IssueHarvester(HttpClient httpClient, ILogger<IssueHarvester> logger, string outputDirectory)
    {
        _httpClient = httpClient;
        _logger = logger;
        _outputDirectory = outputDirectory;
        Directory.CreateDirectory(_outputDirectory);
    }

    /// <summary>
    /// Performs a full scraping cycle across all target sources.
    /// </summary>
    public async Task<HarvestReport> HarvestAsync(CancellationToken ct = default)
    {
        _logger.LogInformation("Starting issue harvest cycle...");
        var report = new HarvestReport { HarvestedAt = DateTimeOffset.UtcNow };

        foreach (var url in TargetUrls)
        {
            try
            {
                var issues = await ScrapePageAsync(url, ct);
                report.Issues.AddRange(issues);
                _logger.LogInformation("Scraped {Count} issues from {Url}", issues.Count, url);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to scrape {Url}", url);
                report.Errors.Add($"Failed: {url} — {ex.Message}");
            }
        }

        report.TotalIssuesFound = report.Issues.Count;
        await SaveReportAsync(report, ct);
        return report;
    }

    private async Task<List<ScrapedIssue>> ScrapePageAsync(string url, CancellationToken ct)
    {
        var html = await _httpClient.GetStringAsync(url, ct);
        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        var issues = new List<ScrapedIssue>();

        // Extract issue titles and descriptions from common Microsoft support patterns
        var contentNodes = doc.DocumentNode.SelectNodes(
            "//div[contains(@class,'content')]//h2 | //div[contains(@class,'content')]//h3 | //table//tr");

        if (contentNodes is null) return issues;

        foreach (var node in contentNodes)
        {
            var title = node.InnerText?.Trim();
            if (string.IsNullOrWhiteSpace(title) || title.Length < 10) continue;

            issues.Add(new ScrapedIssue
            {
                Title = HtmlEntity.DeEntitize(title),
                SourceUrl = url,
                ScrapedAt = DateTimeOffset.UtcNow,
                Severity = ClassifySeverity(title),
                Category = ClassifyCategory(title)
            });
        }

        return issues;
    }

    private static IssueSeverity ClassifySeverity(string title)
    {
        var lower = title.ToLowerInvariant();
        if (lower.Contains("bsod") || lower.Contains("freeze") || lower.Contains("crash"))
            return IssueSeverity.Critical;
        if (lower.Contains("fail") || lower.Contains("error") || lower.Contains("broken"))
            return IssueSeverity.High;
        if (lower.Contains("slow") || lower.Contains("performance") || lower.Contains("delay"))
            return IssueSeverity.Medium;
        return IssueSeverity.Low;
    }

    private static IssueCategory ClassifyCategory(string title)
    {
        var lower = title.ToLowerInvariant();
        if (lower.Contains("driver") || lower.Contains("gpu") || lower.Contains("audio"))
            return IssueCategory.Driver;
        if (lower.Contains("update") || lower.Contains("kb") || lower.Contains("patch"))
            return IssueCategory.Update;
        if (lower.Contains("security") || lower.Contains("vuln") || lower.Contains("cve"))
            return IssueCategory.Security;
        if (lower.Contains("ssd") || lower.Contains("disk") || lower.Contains("storage"))
            return IssueCategory.Storage;
        return IssueCategory.General;
    }

    private async Task SaveReportAsync(HarvestReport report, CancellationToken ct)
    {
        var fileName = $"harvest_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
        var filePath = Path.Combine(_outputDirectory, fileName);
        var json = JsonSerializer.Serialize(report, HarvestJsonContext.Default.HarvestReport);
        await File.WriteAllTextAsync(filePath, json, ct);
        _logger.LogInformation("Harvest report saved to {Path}", filePath);
    }

    public void Dispose() => _httpClient.Dispose();
}

// ─── Data Models ───────────────────────────────────────────────
public sealed class HarvestReport
{
    public DateTimeOffset HarvestedAt { get; set; }
    public int TotalIssuesFound { get; set; }
    public List<ScrapedIssue> Issues { get; set; } = [];
    public List<string> Errors { get; set; } = [];
}

public sealed class ScrapedIssue
{
    public string Title { get; set; } = "";
    public string SourceUrl { get; set; } = "";
    public DateTimeOffset ScrapedAt { get; set; }
    public IssueSeverity Severity { get; set; }
    public IssueCategory Category { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter<IssueSeverity>))]
public enum IssueSeverity { Low, Medium, High, Critical }

[JsonConverter(typeof(JsonStringEnumConverter<IssueCategory>))]
public enum IssueCategory { General, Driver, Update, Security, Storage }

[JsonSerializable(typeof(HarvestReport))]
internal partial class HarvestJsonContext : JsonSerializerContext { }
