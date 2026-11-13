// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — wire models for the telemetry API contract (schema 1)
// Strictly aligned with Infrastructure/telemetry-ingest/schema/v1/event.schema.json
// ─────────────────────────────────────────────────────────────────────────────

using System.Text.Json;
using System.Text.Json.Serialization;

namespace OmniPulse;

/// <summary>Event envelope: one per line in the queue and in NDJSON batches.</summary>
public sealed class TelemetryEnvelope
{
    public const int SchemaVersion = 1;

    [JsonPropertyName("schema")] public int Schema { get; set; } = SchemaVersion;
    /// <summary>Standard hyphenated UUID (v4), matching ^[0-9A-Fa-f]{8}-...-[0-9A-Fa-f]{12}$.</summary>
    [JsonPropertyName("eventId")] public string EventId { get; set; } = "";
    /// <summary>crash | error | usage | scan | baseline</summary>
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    /// <summary>UTC, ISO-8601 RFC 3339.</summary>
    [JsonPropertyName("ts")] public string Ts { get; set; } = "";
    [JsonPropertyName("installId")] public string InstallId { get; set; } = "";
    [JsonPropertyName("appVersion")] public string AppVersion { get; set; } = "";
    [JsonPropertyName("osBuild")] public string OsBuild { get; set; } = "";
    [JsonPropertyName("arch")] public string Arch { get; set; } = "";
    /// <summary>free | community | pro</summary>
    [JsonPropertyName("tier")] public string Tier { get; set; } = "";
    /// <summary>Coarse region label only: EU | GB | CH | unknown (or two-letter ISO).</summary>
    [JsonPropertyName("region")] public string Region { get; set; } = "";
    [JsonPropertyName("payload")] public JsonElement Payload { get; set; }
}

/// <summary>Inner exception entry for payload.crash.</summary>
public sealed class CrashInnerException
{
    [JsonPropertyName("exceptionType")] public string ExceptionType { get; set; } = "";
    [JsonPropertyName("message"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Message { get; set; }
}

/// <summary>Crash payload matching #/$defs/payload.crash in event.schema.json.</summary>
public sealed class CrashPayload
{
    [JsonPropertyName("exceptionType")] public string ExceptionType { get; set; } = "";
    [JsonPropertyName("message"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Message { get; set; }
    [JsonPropertyName("hresult"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? HResult { get; set; }
    [JsonPropertyName("frames")] public List<string> Frames { get; set; } = new();
    [JsonPropertyName("inner"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<CrashInnerException>? Inner { get; set; }
    [JsonPropertyName("component"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Component { get; set; }
    [JsonPropertyName("isFatal"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public bool? IsFatal { get; set; }
    [JsonPropertyName("uptimeSec"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? UptimeSec { get; set; }

    // C# aliases for local callers/tests; omitted from wire JSON because event.schema.json has additionalProperties:false
    // and fingerprint is a server-owned field computed on ingest.
    [JsonIgnore] public string ScrubbedMessage { get => Message ?? ""; set => Message = value; }
    [JsonIgnore] public List<string> Stack { get => Frames; set => Frames = value; }
    [JsonIgnore] public string Module { get => Component ?? ""; set => Component = value; }
    [JsonIgnore] public string Fingerprint { get; set; } = "";
}

/// <summary>Non-fatal error payload matching #/$defs/payload.error in event.schema.json.</summary>
public sealed class ErrorPayload
{
    [JsonPropertyName("code")] public string Code { get; set; } = "";
    [JsonPropertyName("component")] public string Component { get; set; } = "";
    [JsonPropertyName("severity"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Severity { get; set; }
    [JsonPropertyName("message"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Message { get; set; }
    [JsonPropertyName("hresult"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? HResult { get; set; }
    [JsonPropertyName("frames"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string>? Frames { get; set; }
}

/// <summary>Key-value pair for payload.usage.props.</summary>
public sealed class TelemetryProp
{
    [JsonPropertyName("k")] public string Key { get; set; } = "";
    [JsonPropertyName("v")] public string Value { get; set; } = "";
}

/// <summary>Feature usage payload matching #/$defs/payload.usage in event.schema.json.</summary>
public sealed class UsagePayload
{
    [JsonPropertyName("feature")] public string Feature { get; set; } = "";
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("durationMs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? DurationMs { get; set; }
    [JsonPropertyName("count"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? Count { get; set; }
    [JsonPropertyName("props"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<TelemetryProp>? Props { get; set; }
}

/// <summary>Issue count entry for payload.scan.issues.</summary>
public sealed class ScanIssueCount
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("count"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? Count { get; set; }
}

/// <summary>Scan summary payload matching #/$defs/payload.scan in event.schema.json.</summary>
public sealed class ScanPayload
{
    [JsonPropertyName("scanType")] public string ScanType { get; set; } = "";
    [JsonPropertyName("durationMs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? DurationMs { get; set; }
    [JsonPropertyName("itemsFound"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? ItemsFound { get; set; }
    [JsonPropertyName("bytesReclaimable"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? BytesReclaimable { get; set; }
    [JsonPropertyName("healthScore"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public int? HealthScore { get; set; }
    [JsonPropertyName("modulesRun"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string>? ModulesRun { get; set; }
    [JsonPropertyName("issues"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<ScanIssueCount>? Issues { get; set; }
}

/// <summary>Windows version sub-object for payload.baseline.</summary>
public sealed class BaselineWindows
{
    [JsonPropertyName("edition"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Edition { get; set; }
    [JsonPropertyName("displayVersion"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? DisplayVersion { get; set; }
    [JsonPropertyName("ubr"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? Ubr { get; set; }
}

/// <summary>GPU entry for payload.baseline.hardware.gpus.</summary>
public sealed class BaselineGpu
{
    [JsonPropertyName("vendor"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Vendor { get; set; }
    [JsonPropertyName("name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Name { get; set; }
    [JsonPropertyName("driverVersion"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? DriverVersion { get; set; }
    [JsonPropertyName("driverDate"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? DriverDate { get; set; }
}

/// <summary>Hardware summary sub-object for payload.baseline.</summary>
public sealed class BaselineHardware
{
    [JsonPropertyName("cpuName"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? CpuName { get; set; }
    [JsonPropertyName("cpuCores"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? CpuCores { get; set; }
    [JsonPropertyName("ramGb"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public double? RamGb { get; set; }
    [JsonPropertyName("gpus"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<BaselineGpu>? Gpus { get; set; }
    [JsonPropertyName("biosVendor"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? BiosVendor { get; set; }
    [JsonPropertyName("biosVersion"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? BiosVersion { get; set; }
    [JsonPropertyName("boardVendor"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? BoardVendor { get; set; }
    [JsonPropertyName("boardModel"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? BoardModel { get; set; }
    [JsonPropertyName("diskTypes"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string>? DiskTypes { get; set; }
}

/// <summary>Driver inventory item for payload.baseline.drivers.</summary>
public sealed class BaselineDriver
{
    [JsonPropertyName("class"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Class { get; set; }
    [JsonPropertyName("vendor"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Vendor { get; set; }
    [JsonPropertyName("name"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Name { get; set; }
    [JsonPropertyName("version"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Version { get; set; }
    [JsonPropertyName("date"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Date { get; set; }
    [JsonPropertyName("hwidClass"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? HwidClass { get; set; }
}

/// <summary>System baseline payload matching #/$defs/payload.baseline in event.schema.json.</summary>
public sealed class BaselinePayload
{
    [JsonPropertyName("windows"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public BaselineWindows? Windows { get; set; }
    [JsonPropertyName("hardware"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public BaselineHardware? Hardware { get; set; }
    [JsonPropertyName("drivers"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<BaselineDriver>? Drivers { get; set; }
    [JsonPropertyName("kbs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string>? Kbs { get; set; }
    [JsonPropertyName("securityProducts"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string>? SecurityProducts { get; set; }
    [JsonPropertyName("servicesRunning"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public long? ServicesRunning { get; set; }
}

