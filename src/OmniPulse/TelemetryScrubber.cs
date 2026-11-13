// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — TelemetryScrubber
// Removes personal data from free text and stack traces before anything is
// queued for upload. Local crash logs are NOT scrubbed (they never leave the PC).
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OmniPulse;

/// <summary>Scrubs paths, user/machine names, e-mails, IPs, SIDs and token-like strings.</summary>
public static class TelemetryScrubber
{
    public const int MaxMessageLength = 512;
    public const int MaxStackFrames = 30;

    private static readonly string[] AppPrefixes = { "LogicFlow", "OmniPulse", "OmniLicense", "OmniCore", "DelgadoLogic" };

    private static readonly Regex UserProfile = new(@"(?i)([A-Za-z]:\\Users\\)[^\\/\r\n]+", RegexOptions.Compiled);
    // Everything below a profile folder (documents, file names) is personal: collapse it. Inner components may contain spaces, the last one may not.
    private static readonly Regex ProfileTail = new(@"(?<=<user>)(?:\\[^\\/:*?""<>|\r\n]+(?=\\))*\\[^\s\\/:*?""<>|]*", RegexOptions.Compiled);
    private static readonly Regex DrivePath = new(@"[A-Za-z]:\\(?:[^\\/:*?""<>|\r\n]+\\)+", RegexOptions.Compiled);
    private static readonly Regex UncPath = new(@"\\\\[^\s\\/]+(?:\\[^\s\\/]+)*", RegexOptions.Compiled);
    private static readonly Regex UrlQuery = new(@"(https?://[^\s?#]+)\?[^\s]*", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex Email = new(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled);
    private static readonly Regex Sid = new(@"\bS-1-\d+(?:-\d+)+\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex Ipv4 = new(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", RegexOptions.Compiled);
    private static readonly Regex Ipv6 = new(@"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|(?<![\w:])(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![\w:])", RegexOptions.Compiled);
    private static readonly Regex LongToken = new(@"[A-Za-z0-9+/_\-=]{32,}", RegexOptions.Compiled);
    private static readonly Regex FrameArgs = new(@"\(.*$", RegexOptions.Compiled);
    private static readonly Regex FrameIn = new(@"\s+in\s+.*$", RegexOptions.Compiled);

    /// <summary>Scrubs free text. <paramref name="userName"/>/<paramref name="machineName"/> default to the current ones; <paramref name="maskTokens"/> hides 32+ char opaque strings.</summary>
    public static string ScrubText(string? text, string? userName = null, string? machineName = null, bool maskTokens = true)
    {
        if (string.IsNullOrEmpty(text)) return "";

        var s = text;
        s = UncPath.Replace(s, "<unc>");
        s = UserProfile.Replace(s, "$1<user>");
        s = ProfileTail.Replace(s, @"\<path>");
        s = DrivePath.Replace(s, @"<path>\");
        s = UrlQuery.Replace(s, "$1?<q>");
        s = Email.Replace(s, "<email>");
        s = Sid.Replace(s, "<sid>");
        s = Ipv4.Replace(s, "<ip>");
        s = Ipv6.Replace(s, "<ip>");
        if (maskTokens) s = LongToken.Replace(s, "<token>");

        foreach (var name in new[] { userName ?? SafeEnv(() => Environment.UserName), machineName ?? SafeEnv(() => Environment.MachineName) })
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length < 3) continue;
            s = Regex.Replace(s, @"(?<![A-Za-z0-9])" + Regex.Escape(name) + @"(?![A-Za-z0-9])", "<name>", RegexOptions.IgnoreCase);
        }

        return s.Length > MaxMessageLength ? s[..MaxMessageLength] : s;
    }

    /// <summary>Reduces a .NET stack trace to "Namespace.Type.Method" frames (no args, files or line numbers).</summary>
    public static List<string> NormalizeStack(string? stackTrace)
    {
        var frames = new List<string>();
        if (string.IsNullOrWhiteSpace(stackTrace)) return frames;

        foreach (var raw in stackTrace.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("at ", StringComparison.Ordinal)) continue;

            line = FrameIn.Replace(line[3..], "");
            line = FrameArgs.Replace(line, "").Trim();
            if (line.Length == 0) continue;

            frames.Add(line.Length > 200 ? line[..200] : line);
            if (frames.Count >= MaxStackFrames) break;
        }
        return frames;
    }

    /// <summary>sha256(exceptionType + top-3 in-app frames), lowercase hex. Falls back to the first 3 frames.</summary>
    public static string Fingerprint(string exceptionType, IReadOnlyList<string> frames)
    {
        var top = frames.Where(IsAppFrame).Take(3).ToList();
        if (top.Count == 0) top = frames.Take(3).ToList();

        var material = exceptionType + "\n" + string.Join("\n", top);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    /// <summary>Builds a schema v1 crash payload from raw exception data.</summary>
    public static CrashPayload BuildCrashPayload(string exceptionType, string? message, string? stackTrace, string? moduleOverride = null)
    {
        var type = Truncate(ScrubText(exceptionType), 200, "Unknown");
        var frames = NormalizeStack(stackTrace);
        var comp = ScrubText(moduleOverride) is { Length: > 0 } m ? Truncate(m, 64, "unknown") : Truncate(ModuleOf(frames), 64, "unknown");

        return new CrashPayload
        {
            ExceptionType = type,
            Message = ScrubText(message),
            Frames = frames,
            Component = comp,
            IsFatal = true,
            Fingerprint = Fingerprint(type, frames)
        };
    }

    public static CrashPayload BuildCrashPayload(Exception ex, string? moduleOverride = null)
    {
        var payload = BuildCrashPayload(ex.GetType().FullName ?? ex.GetType().Name, ex.Message, ex.StackTrace, moduleOverride);
        payload.HResult = $"0x{ex.HResult:X8}";

        var inner = new List<CrashInnerException>();
        var cur = ex.InnerException;
        while (cur is not null && inner.Count < 5)
        {
            inner.Add(new CrashInnerException
            {
                ExceptionType = Truncate(ScrubText(cur.GetType().FullName ?? cur.GetType().Name), 200, "Unknown"),
                Message = ScrubText(cur.Message)
            });
            cur = cur.InnerException;
        }
        if (inner.Count > 0) payload.Inner = inner;
        return payload;
    }

    /// <summary>Builds a schema v1 non-fatal error payload (#/$defs/payload.error).</summary>
    public static ErrorPayload BuildErrorPayload(string engineName, string methodName, Exception ex, string? context = null)
    {
        var code = Truncate(ScrubText(ex.GetType().Name), 64, "Error");
        var comp = Truncate(ScrubText($"{engineName}.{methodName}"), 64, "unknown");
        var rawMsg = string.IsNullOrWhiteSpace(context) ? ex.Message : $"{context}: {ex.Message}";
        return new ErrorPayload
        {
            Code = code,
            Component = comp,
            Severity = "error",
            Message = ScrubText(rawMsg),
            HResult = $"0x{ex.HResult:X8}",
            Frames = NormalizeStack(ex.StackTrace)
        };
    }

    internal static string Truncate(string? value, int maxLength, string fallback = "")
    {
        if (string.IsNullOrWhiteSpace(value)) return fallback;
        var s = value.Trim();
        return s.Length > maxLength ? s[..maxLength] : s;
    }

    private static bool IsAppFrame(string frame)
        => AppPrefixes.Any(p => frame.StartsWith(p, StringComparison.Ordinal));

    private static string ModuleOf(IReadOnlyList<string> frames)
    {
        var frame = frames.FirstOrDefault(IsAppFrame) ?? frames.FirstOrDefault();
        if (frame is null) return "unknown";

        var parts = frame.Split('.');
        return parts.Length >= 3 ? string.Join('.', parts.Take(Math.Min(2, parts.Length - 2))) : parts[0];
    }

    private static string SafeEnv(Func<string> get)
    {
        try { return get(); } catch { return ""; }
    }
}
