// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — BrowserPrivacyCleanerEngine
// Per-Browser SQLite Cookie/Session Whitelist Cleaner & Database Vacuum Engine.
// Supports Chrome, Edge, Brave, Opera, Vivaldi, and Firefox profiles.
// Uses native Windows winsqlite3.dll (System32) for zero-dependency SQLite 3
// cookie pruning and page compaction (PRAGMA wal_checkpoint + VACUUM).
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

public sealed class BrowserPrivacyCleanerEngine
{
    private readonly ILogger<BrowserPrivacyCleanerEngine>? _logger;
    private readonly string _whitelistFilePath;
    private readonly Func<BrowserType, bool>? _customRunningCheck;

    public static readonly IReadOnlyList<string> DefaultWhitelistedDomains =
    [
        "google.com",
        "github.com",
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "discord.com",
        "steampowered.com",
        "cloudflare.com"
    ];

    public enum BrowserType
    {
        Chrome,
        Edge,
        Brave,
        Opera,
        Vivaldi,
        Firefox
    }

    public sealed class BrowserProfileInfo
    {
        public BrowserType Browser { get; init; }
        public string BrowserName { get; init; } = "";
        public string ProfileName { get; init; } = "";
        public string ProfilePath { get; init; } = "";
        public string? CookiesDbPath { get; init; }
        public List<string> SqliteDatabasePaths { get; init; } = new();
        public bool IsBrowserRunning { get; set; }
        public int TotalCookies { get; set; }
        public int WhitelistedCookies { get; set; }
        public int TrackingCookies { get; set; }
        public long TotalSqliteSizeBytes { get; set; }
        public long EstimatedVacuumSavingsBytes { get; set; }
        public string TotalSqliteSizeFormatted => FormatBytes(TotalSqliteSizeBytes);
        public string EstimatedVacuumSavingsFormatted => FormatBytes(EstimatedVacuumSavingsBytes);
    }

    public sealed class BrowserProfileCleanResult
    {
        public BrowserType Browser { get; init; }
        public string BrowserName { get; init; } = "";
        public string ProfileName { get; init; } = "";
        public string ProfilePath { get; init; } = "";
        public bool SkippedBecauseRunning { get; set; }
        public int CookiesRemoved { get; set; }
        public int CookiesPreserved { get; set; }
        public int DatabasesVacuumed { get; set; }
        public long BytesReclaimed { get; set; }
        public string BytesReclaimedFormatted => FormatBytes(BytesReclaimed);
        public List<string> Messages { get; init; } = new();
    }

    public sealed class BrowserPrivacyCleanReport
    {
        public bool DryRun { get; init; }
        public bool VacuumExecuted { get; init; }
        public List<string> WhitelistedDomains { get; init; } = new();
        public List<BrowserProfileCleanResult> Profiles { get; init; } = new();
        public int TotalProfilesScanned => Profiles.Count;
        public int ProfilesCleaned => Profiles.Count(p => !p.SkippedBecauseRunning);
        public int ProfilesSkippedRunning => Profiles.Count(p => p.SkippedBecauseRunning);
        public int TotalCookiesRemoved => Profiles.Sum(p => p.CookiesRemoved);
        public int TotalCookiesPreserved => Profiles.Sum(p => p.CookiesPreserved);
        public int TotalDatabasesVacuumed => Profiles.Sum(p => p.DatabasesVacuumed);
        public long TotalBytesReclaimed => Profiles.Sum(p => p.BytesReclaimed);
        public string TotalBytesReclaimedFormatted => FormatBytes(TotalBytesReclaimed);
    }

    public BrowserPrivacyCleanerEngine(
        ILogger<BrowserPrivacyCleanerEngine>? logger = null,
        string? whitelistFilePath = null,
        Func<BrowserType, bool>? customRunningCheck = null)
    {
        _logger = logger;
        _customRunningCheck = customRunningCheck;
        _whitelistFilePath = whitelistFilePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow",
            "browser_whitelist.json");
    }

    // ─── Whitelist Management ────────────────────────────────────────────

    public List<string> GetWhitelistedDomains()
    {
        try
        {
            if (File.Exists(_whitelistFilePath))
            {
                var json = File.ReadAllText(_whitelistFilePath);
                var loaded = JsonSerializer.Deserialize<List<string>>(json);
                if (loaded is { Count: > 0 })
                {
                    return loaded
                        .Select(NormalizeDomain)
                        .Where(d => !string.IsNullOrWhiteSpace(d))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                        .ToList();
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Could not load browser whitelist from {Path}; using defaults.", _whitelistFilePath);
        }

        var defaults = DefaultWhitelistedDomains.ToList();
        SaveWhitelistInternal(defaults);
        return defaults;
    }

    public List<string> AddWhitelistedDomain(string domain)
    {
        var normalized = NormalizeDomain(domain);
        var current = GetWhitelistedDomains();
        if (!string.IsNullOrWhiteSpace(normalized) &&
            !current.Contains(normalized, StringComparer.OrdinalIgnoreCase))
        {
            current.Add(normalized);
            current.Sort(StringComparer.OrdinalIgnoreCase);
            SaveWhitelistInternal(current);
        }
        return current;
    }

    public List<string> RemoveWhitelistedDomain(string domain)
    {
        var normalized = NormalizeDomain(domain);
        var current = GetWhitelistedDomains();
        if (!string.IsNullOrWhiteSpace(normalized))
        {
            current.RemoveAll(d => string.Equals(d, normalized, StringComparison.OrdinalIgnoreCase));
            SaveWhitelistInternal(current);
        }
        return current;
    }

    public List<string> SetWhitelistedDomains(IEnumerable<string> domains)
    {
        var normalized = (domains ?? Array.Empty<string>())
            .Select(NormalizeDomain)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
            .ToList();
        SaveWhitelistInternal(normalized);
        return normalized;
    }

    public List<string> ResetWhitelistToDefaults()
    {
        var defaults = DefaultWhitelistedDomains
            .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
            .ToList();
        SaveWhitelistInternal(defaults);
        return defaults;
    }

    private void SaveWhitelistInternal(List<string> domains)
    {
        try
        {
            var dir = Path.GetDirectoryName(_whitelistFilePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(domains, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_whitelistFilePath, json);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to persist browser whitelist to {Path}", _whitelistFilePath);
        }
    }

    public static string NormalizeDomain(string? rawDomain)
    {
        if (string.IsNullOrWhiteSpace(rawDomain))
            return string.Empty;

        string d = rawDomain.Trim().ToLowerInvariant();
        if (d.StartsWith("https://", StringComparison.Ordinal))
            d = d["https://".Length..];
        else if (d.StartsWith("http://", StringComparison.Ordinal))
            d = d["http://".Length..];

        int slashIdx = d.IndexOf('/');
        if (slashIdx >= 0)
            d = d[..slashIdx];

        int colonIdx = d.IndexOf(':');
        if (colonIdx >= 0)
            d = d[..colonIdx];

        d = d.Trim().Trim('.');
        if (d.StartsWith("www.", StringComparison.Ordinal) && d.Length > 4 && d[4..].Contains('.'))
            d = d[4..];

        return d;
    }

    /// <summary>
    /// Evaluates whether a browser cookie's host_key / host matches any whitelisted domain
    /// (exact match or subdomain match, e.g. ".accounts.google.com" matches "google.com").
    /// </summary>
    public static bool IsDomainWhitelisted(string? cookieHost, IEnumerable<string>? whitelist)
    {
        if (string.IsNullOrWhiteSpace(cookieHost) || whitelist is null)
            return false;

        string host = cookieHost.Trim().Trim('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(host))
            return false;

        foreach (var rawAllowed in whitelist)
        {
            string allowed = NormalizeDomain(rawAllowed);
            if (string.IsNullOrEmpty(allowed))
                continue;

            if (string.Equals(host, allowed, StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    // ─── Running Process & Lock Detection ────────────────────────────────

    public bool IsBrowserRunning(BrowserType browser)
    {
        if (_customRunningCheck is not null)
            return _customRunningCheck(browser);

        string[] processNames = browser switch
        {
            BrowserType.Chrome => ["chrome"],
            BrowserType.Edge => ["msedge"],
            BrowserType.Brave => ["brave"],
            BrowserType.Opera => ["opera"],
            BrowserType.Vivaldi => ["vivaldi"],
            BrowserType.Firefox => ["firefox"],
            _ => []
        };

        foreach (var procName in processNames)
        {
            try
            {
                var procs = Process.GetProcessesByName(procName);
                bool anyRunning = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
                if (anyRunning)
                    return true;
            }
            catch { }
        }

        return false;
    }

    public static bool IsFileLocked(string filePath)
    {
        if (!File.Exists(filePath))
            return false;

        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    public static bool CanOpenForWrite(string filePath)
    {
        if (!File.Exists(filePath))
            return false;

        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            string walPath = filePath + "-wal";
            if (File.Exists(walPath))
            {
                using var walStream = new FileStream(walPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            }
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void CopyFileShared(string sourcePath, string destinationPath)
    {
        using var src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var dst = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None);
        src.CopyTo(dst);
    }

    // ─── Profile Discovery ───────────────────────────────────────────────

    public List<BrowserProfileInfo> DiscoverProfiles(string? customLocalAppData = null, string? customRoamingAppData = null)
    {
        var profiles = new List<BrowserProfileInfo>();
        var whitelist = GetWhitelistedDomains();

        string localAppData = customLocalAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roamingAppData = customRoamingAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var chromiumRoots = new (BrowserType Type, string Name, string RootPath, bool SingleProfileRoot)[]
        {
            (BrowserType.Chrome, "Google Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data"), false),
            (BrowserType.Edge, "Microsoft Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data"), false),
            (BrowserType.Brave, "Brave Browser", Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data"), false),
            (BrowserType.Vivaldi, "Vivaldi", Path.Combine(localAppData, "Vivaldi", "User Data"), false),
            (BrowserType.Opera, "Opera", Path.Combine(roamingAppData, "Opera Software", "Opera Stable"), true),
            (BrowserType.Opera, "Opera GX", Path.Combine(roamingAppData, "Opera Software", "Opera GX Stable"), true),
        };

        foreach (var (type, name, rootPath, singleProfileRoot) in chromiumRoots)
        {
            if (!Directory.Exists(rootPath))
                continue;

            var candidateDirs = new List<string>();
            if (singleProfileRoot)
            {
                candidateDirs.Add(rootPath);
                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(rootPath, "Profile *"))
                        candidateDirs.Add(sub);
                }
                catch { }
            }
            else
            {
                var defaultDir = Path.Combine(rootPath, "Default");
                if (Directory.Exists(defaultDir))
                    candidateDirs.Add(defaultDir);

                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(rootPath, "Profile *"))
                        candidateDirs.Add(sub);
                }
                catch { }
            }

            foreach (var profileDir in candidateDirs)
            {
                var cookiesNetworkPath = Path.Combine(profileDir, "Network", "Cookies");
                var cookiesLegacyPath = Path.Combine(profileDir, "Cookies");
                string? cookiesPath = File.Exists(cookiesNetworkPath)
                    ? cookiesNetworkPath
                    : (File.Exists(cookiesLegacyPath) ? cookiesLegacyPath : null);

                var sqlitePaths = new List<string>();
                if (cookiesPath != null)
                    sqlitePaths.Add(cookiesPath);

                foreach (var dbName in new[] { "History", "Web Data", "Favicons", "Top Sites", "Shortcuts" })
                {
                    var dbCandidate = Path.Combine(profileDir, dbName);
                    if (File.Exists(dbCandidate) && IsSqliteHeader(dbCandidate))
                        sqlitePaths.Add(dbCandidate);
                }

                if (sqlitePaths.Count == 0)
                    continue;

                var info = new BrowserProfileInfo
                {
                    Browser = type,
                    BrowserName = name,
                    ProfileName = singleProfileRoot ? "Default" : Path.GetFileName(profileDir),
                    ProfilePath = profileDir,
                    CookiesDbPath = cookiesPath,
                    SqliteDatabasePaths = sqlitePaths,
                    IsBrowserRunning = IsBrowserRunning(type),
                    TotalSqliteSizeBytes = sqlitePaths.Sum(GetSqliteFootprintBytes)
                };

                InspectProfileMetrics(info, whitelist, isFirefox: false);
                profiles.Add(info);
            }
        }

        // Firefox profiles (%APPDATA%\Mozilla\Firefox\Profiles)
        var firefoxRoot = Path.Combine(roamingAppData, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxRoot))
        {
            try
            {
                foreach (var profileDir in Directory.EnumerateDirectories(firefoxRoot))
                {
                    var cookiesPath = Path.Combine(profileDir, "cookies.sqlite");
                    var sqlitePaths = new List<string>();
                    if (File.Exists(cookiesPath))
                        sqlitePaths.Add(cookiesPath);

                    foreach (var dbName in new[] { "places.sqlite", "formhistory.sqlite", "favicons.sqlite", "webappsstore.sqlite" })
                    {
                        var dbCandidate = Path.Combine(profileDir, dbName);
                        if (File.Exists(dbCandidate))
                            sqlitePaths.Add(dbCandidate);
                    }

                    if (sqlitePaths.Count == 0)
                        continue;

                    var info = new BrowserProfileInfo
                    {
                        Browser = BrowserType.Firefox,
                        BrowserName = "Mozilla Firefox",
                        ProfileName = Path.GetFileName(profileDir),
                        ProfilePath = profileDir,
                        CookiesDbPath = File.Exists(cookiesPath) ? cookiesPath : null,
                        SqliteDatabasePaths = sqlitePaths,
                        IsBrowserRunning = IsBrowserRunning(BrowserType.Firefox),
                        TotalSqliteSizeBytes = sqlitePaths.Sum(GetSqliteFootprintBytes)
                    };

                    InspectProfileMetrics(info, whitelist, isFirefox: true);
                    profiles.Add(info);
                }
            }
            catch { }
        }

        return profiles;
    }

    // ─── Clean & Vacuum Execution ────────────────────────────────────────

    public BrowserPrivacyCleanReport CleanProfiles(
        bool vacuumDatabases = true,
        bool dryRun = false,
        IEnumerable<string>? overrideWhitelist = null,
        IEnumerable<BrowserProfileInfo>? explicitProfiles = null,
        bool clearHistory = false)
    {
        var whitelist = (overrideWhitelist ?? GetWhitelistedDomains())
            .Select(NormalizeDomain)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var profiles = explicitProfiles?.ToList() ?? DiscoverProfiles();
        var results = new List<BrowserProfileCleanResult>();

        foreach (var profile in profiles)
        {
            var profileResult = new BrowserProfileCleanResult
            {
                Browser = profile.Browser,
                BrowserName = profile.BrowserName,
                ProfileName = profile.ProfileName,
                ProfilePath = profile.ProfilePath
            };

            bool running = IsBrowserRunning(profile.Browser);
            profileResult.SkippedBecauseRunning = running;
            if (running && !dryRun)
            {
                profileResult.Messages.Add($"{profile.BrowserName} ({profile.ProfileName}) is currently running; skipped to prevent SQLite lock corruption.");
                results.Add(profileResult);
                continue;
            }

            bool isFirefox = profile.Browser == BrowserType.Firefox;

            // 1. Clean cookies DB if present
            if (!string.IsNullOrEmpty(profile.CookiesDbPath) && File.Exists(profile.CookiesDbPath))
            {
                var (removed, preserved, reclaimed, vacuumed) = CleanAndVacuumSqliteDatabase(
                    profile.CookiesDbPath,
                    whitelist,
                    isCookieDb: true,
                    isFirefox: isFirefox,
                    vacuum: vacuumDatabases,
                    dryRun: dryRun,
                    clearHistory: false);

                profileResult.CookiesRemoved += removed;
                profileResult.CookiesPreserved += preserved;
                profileResult.BytesReclaimed += reclaimed;
                if (vacuumed)
                    profileResult.DatabasesVacuumed++;
            }

            // 2. Vacuum auxiliary SQLite databases (History, Web Data, places.sqlite, etc.)
            if (vacuumDatabases || clearHistory)
            {
                foreach (var dbPath in profile.SqliteDatabasePaths)
                {
                    if (string.Equals(dbPath, profile.CookiesDbPath, StringComparison.OrdinalIgnoreCase))
                        continue;

                    var (_, _, reclaimed, vacuumed) = CleanAndVacuumSqliteDatabase(
                        dbPath,
                        whitelist,
                        isCookieDb: false,
                        isFirefox: isFirefox,
                        vacuum: vacuumDatabases,
                        dryRun: dryRun,
                        clearHistory: clearHistory);

                    profileResult.BytesReclaimed += reclaimed;
                    if (vacuumed)
                        profileResult.DatabasesVacuumed++;
                }
            }

            string statusNote = running && dryRun ? " [Browser currently running — close before live clean]" : "";
            profileResult.Messages.Add(
                $"{profile.BrowserName} [{profile.ProfileName}]: {profileResult.CookiesRemoved} tracking cookies removed, " +
                $"{profileResult.CookiesPreserved} whitelisted cookies kept, {profileResult.DatabasesVacuumed} SQLite DBs vacuumed ({profileResult.BytesReclaimedFormatted} reclaimed).{statusNote}");

            results.Add(profileResult);
        }

        return new BrowserPrivacyCleanReport
        {
            DryRun = dryRun,
            VacuumExecuted = vacuumDatabases,
            WhitelistedDomains = whitelist,
            Profiles = results
        };
    }

    /// <summary>
    /// Prunes non-whitelisted cookies from a Chromium or Firefox SQLite database and/or
    /// executes PRAGMA wal_checkpoint(TRUNCATE), PRAGMA optimize, and VACUUM.
    /// </summary>
    public (int Removed, int Preserved, long BytesReclaimed, bool Vacuumed) CleanAndVacuumSqliteDatabase(
        string dbPath,
        IEnumerable<string> whitelist,
        bool isCookieDb,
        bool isFirefox,
        bool vacuum = true,
        bool dryRun = false,
        bool clearHistory = false)
    {
        if (!File.Exists(dbPath))
            return (0, 0, 0, false);

        if (!dryRun && !CanOpenForWrite(dbPath))
            return (0, 0, 0, false);

        long sizeBefore = GetSqliteFootprintBytes(dbPath);
        int removed = 0;
        int preserved = 0;
        bool vacuumed = false;

        string targetOpenPath = dbPath;
        string? tempCopyPath = null;

        try
        {
            bool hasWal = File.Exists(dbPath + "-wal");
            if (dryRun && (IsFileLocked(dbPath) || hasWal))
            {
                tempCopyPath = Path.Combine(Path.GetTempPath(), $"lf_sqlite_inspect_{Guid.NewGuid():N}.db");
                CopyFileShared(dbPath, tempCopyPath);
                if (hasWal)
                {
                    try { CopyFileShared(dbPath + "-wal", tempCopyPath + "-wal"); } catch { }
                }
                targetOpenPath = tempCopyPath;
            }

            int flags = (dryRun && tempCopyPath == null)
                ? (WinSqlite3.SQLITE_OPEN_READONLY | WinSqlite3.SQLITE_OPEN_NOMUTEX)
                : (WinSqlite3.SQLITE_OPEN_READWRITE | WinSqlite3.SQLITE_OPEN_NOMUTEX);

            if (WinSqlite3.sqlite3_open_v2(targetOpenPath, out IntPtr db, flags, IntPtr.Zero) != WinSqlite3.SQLITE_OK)
            {
                if (db != IntPtr.Zero)
                    WinSqlite3.sqlite3_close_v2(db);
                return (0, 0, 0, false);
            }

            try
            {
                WinSqlite3.sqlite3_busy_timeout(db, 1500);

                if (isCookieDb)
                {
                    string tableName = isFirefox ? "moz_cookies" : "cookies";
                    string hostColumn = isFirefox ? "host" : "host_key";
                    string selectSql = $"SELECT rowid, {hostColumn} FROM {tableName};";

                    var rowIdsToDelete = new List<long>();

                    if (WinSqlite3.sqlite3_prepare_v2(db, selectSql, -1, out IntPtr stmt, IntPtr.Zero) == WinSqlite3.SQLITE_OK)
                    {
                        try
                        {
                            while (WinSqlite3.sqlite3_step(stmt) == WinSqlite3.SQLITE_ROW)
                            {
                                long rowId = WinSqlite3.sqlite3_column_int64(stmt, 0);
                                IntPtr hostPtr = WinSqlite3.sqlite3_column_text(stmt, 1);
                                string host = hostPtr != IntPtr.Zero ? (Marshal.PtrToStringUTF8(hostPtr) ?? "") : "";

                                if (IsDomainWhitelisted(host, whitelist))
                                {
                                    preserved++;
                                }
                                else
                                {
                                    rowIdsToDelete.Add(rowId);
                                }
                            }
                        }
                        finally
                        {
                            WinSqlite3.sqlite3_finalize(stmt);
                        }
                    }

                    if (!dryRun && rowIdsToDelete.Count > 0)
                    {
                        if (ExecuteNonQuery(db, "BEGIN IMMEDIATE TRANSACTION;"))
                        {
                            try
                            {
                                // Delete in batches of 200 rowids
                                for (int i = 0; i < rowIdsToDelete.Count; i += 200)
                                {
                                    var batch = rowIdsToDelete.Skip(i).Take(200);
                                    string idList = string.Join(",", batch);
                                    ExecuteNonQuery(db, $"DELETE FROM {tableName} WHERE rowid IN ({idList});");
                                }
                                ExecuteNonQuery(db, "COMMIT;");
                                removed = rowIdsToDelete.Count;
                            }
                            catch
                            {
                                ExecuteNonQuery(db, "ROLLBACK;");
                                throw;
                            }
                        }
                    }
                    else if (dryRun)
                    {
                        removed = rowIdsToDelete.Count;
                    }
                }
                else if (clearHistory && !dryRun)
                {
                    PruneHistoryTables(db, whitelist, isFirefox);
                }

                long estimatedFreelistBytes = QueryFreeSpaceEstimate(db);

                if (!dryRun && vacuum)
                {
                    bool chkBefore = ExecuteNonQuery(db, "PRAGMA wal_checkpoint(TRUNCATE);");
                    ExecuteNonQuery(db, "PRAGMA optimize;");
                    if (ExecuteNonQuery(db, "VACUUM;"))
                    {
                        vacuumed = true;
                    }
                    else if (chkBefore && removed > 0)
                    {
                        vacuumed = true;
                    }
                    ExecuteNonQuery(db, "PRAGMA wal_checkpoint(TRUNCATE);");
                }
                else if (dryRun && vacuum)
                {
                    vacuumed = true;
                    return (removed, preserved, estimatedFreelistBytes + (removed * 256L), true);
                }
            }
            finally
            {
                WinSqlite3.sqlite3_close_v2(db);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "SQLite operation failed on {Path}", dbPath);
        }
        finally
        {
            if (tempCopyPath != null)
            {
                foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
                {
                    var p = tempCopyPath + suffix;
                    if (File.Exists(p))
                    {
                        try { File.Delete(p); } catch { }
                    }
                }
            }
        }

        long sizeAfter = GetSqliteFootprintBytes(dbPath);
        long bytesReclaimed = Math.Max(0, sizeBefore - sizeAfter);
        return (removed, preserved, bytesReclaimed, vacuumed);
    }

    private static void PruneHistoryTables(IntPtr db, IEnumerable<string> whitelist, bool isFirefox)
    {
        string tableName = isFirefox ? "moz_places" : "urls";
        string urlSql = $"SELECT rowid, url FROM {tableName};";
        var rowIdsToDelete = new List<long>();

        if (WinSqlite3.sqlite3_prepare_v2(db, urlSql, -1, out IntPtr stmt, IntPtr.Zero) == WinSqlite3.SQLITE_OK)
        {
            try
            {
                while (WinSqlite3.sqlite3_step(stmt) == WinSqlite3.SQLITE_ROW)
                {
                    long rowId = WinSqlite3.sqlite3_column_int64(stmt, 0);
                    IntPtr urlPtr = WinSqlite3.sqlite3_column_text(stmt, 1);
                    string rawUrl = urlPtr != IntPtr.Zero ? (Marshal.PtrToStringUTF8(urlPtr) ?? "") : "";
                    string host = NormalizeDomain(rawUrl);

                    if (!IsDomainWhitelisted(host, whitelist))
                    {
                        rowIdsToDelete.Add(rowId);
                    }
                }
            }
            finally
            {
                WinSqlite3.sqlite3_finalize(stmt);
            }
        }

        if (rowIdsToDelete.Count > 0 && ExecuteNonQuery(db, "BEGIN IMMEDIATE TRANSACTION;"))
        {
            try
            {
                for (int i = 0; i < rowIdsToDelete.Count; i += 200)
                {
                    var batch = rowIdsToDelete.Skip(i).Take(200);
                    string idList = string.Join(",", batch);
                    ExecuteNonQuery(db, $"DELETE FROM {tableName} WHERE rowid IN ({idList});");
                }
                if (isFirefox)
                    ExecuteNonQuery(db, "DELETE FROM moz_historyvisits WHERE place_id NOT IN (SELECT id FROM moz_places);");
                else
                    ExecuteNonQuery(db, "DELETE FROM visits WHERE url NOT IN (SELECT id FROM urls);");
                ExecuteNonQuery(db, "COMMIT;");
            }
            catch
            {
                ExecuteNonQuery(db, "ROLLBACK;");
            }
        }
    }

    private void InspectProfileMetrics(BrowserProfileInfo info, List<string> whitelist, bool isFirefox)
    {
        if (!string.IsNullOrEmpty(info.CookiesDbPath) && File.Exists(info.CookiesDbPath))
        {
            var (removable, preserved, estReclaim, _) = CleanAndVacuumSqliteDatabase(
                info.CookiesDbPath,
                whitelist,
                isCookieDb: true,
                isFirefox: isFirefox,
                vacuum: true,
                dryRun: true);

            info.TrackingCookies = removable;
            info.WhitelistedCookies = preserved;
            info.TotalCookies = removable + preserved;
            info.EstimatedVacuumSavingsBytes += estReclaim;
        }
    }

    // ─── SQLite Test / Creation Utility ──────────────────────────────────

    /// <summary>
    /// Creates a valid Chromium or Firefox SQLite cookie database populated with the specified cookies.
    /// Useful for deterministic unit and integration verification.
    /// </summary>
    public static void CreateCookieDatabase(
        string dbPath,
        bool isFirefox,
        IEnumerable<(string Host, string Name, string Value)> cookies,
        int paddingBytesPerRow = 512,
        bool useWalMode = false)
    {
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            if (File.Exists(dbPath + suffix))
                File.Delete(dbPath + suffix);
        }

        int flags = WinSqlite3.SQLITE_OPEN_READWRITE | WinSqlite3.SQLITE_OPEN_CREATE | WinSqlite3.SQLITE_OPEN_NOMUTEX;
        int rc = WinSqlite3.sqlite3_open_v2(dbPath, out IntPtr db, flags, IntPtr.Zero);
        if (rc != WinSqlite3.SQLITE_OK)
            throw new InvalidOperationException($"sqlite3_open_v2 failed with code {rc}");

        try
        {
            if (useWalMode)
            {
                ExecuteNonQuery(db, "PRAGMA journal_mode=WAL;");
            }

            if (isFirefox)
            {
                ExecuteNonQuery(db, "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER);");
                ExecuteNonQuery(db, "BEGIN TRANSACTION;");
                int id = 1;
                string pad = new('X', Math.Max(0, paddingBytesPerRow));
                foreach (var (host, name, val) in cookies)
                {
                    string h = host.Replace("'", "''");
                    string n = name.Replace("'", "''");
                    string v = (val + pad).Replace("'", "''");
                    ExecuteNonQuery(db, $"INSERT INTO moz_cookies (id, host, name, value, path, expiry) VALUES ({id++}, '{h}', '{n}', '{v}', '/', 1893456000);");
                }
                ExecuteNonQuery(db, "COMMIT;");
            }
            else
            {
                ExecuteNonQuery(db, "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL);");
                ExecuteNonQuery(db, "BEGIN TRANSACTION;");
                long ts = 13350000000000000L;
                string pad = new('Y', Math.Max(0, paddingBytesPerRow));
                foreach (var (host, name, val) in cookies)
                {
                    string h = host.Replace("'", "''");
                    string n = name.Replace("'", "''");
                    string v = (val + pad).Replace("'", "''");
                    ExecuteNonQuery(db, $"INSERT INTO cookies (creation_utc, host_key, name, value, path, expires_utc) VALUES ({ts++}, '{h}', '{n}', '{v}', '/', 13450000000000000);");
                }
                ExecuteNonQuery(db, "COMMIT;");
            }
        }
        finally
        {
            if (!useWalMode)
            {
                WinSqlite3.sqlite3_close_v2(db);
            }
            else
            {
                // Keep WAL mode intact on disk
                WinSqlite3.sqlite3_close_v2(db);
            }
        }
    }

    // ─── Low-Level Helpers ───────────────────────────────────────────────

    private static bool ExecuteNonQuery(IntPtr db, string sql)
    {
        int rc = WinSqlite3.sqlite3_exec(db, sql, IntPtr.Zero, IntPtr.Zero, out IntPtr errMsg);
        if (errMsg != IntPtr.Zero)
            WinSqlite3.sqlite3_free(errMsg);
        return rc == WinSqlite3.SQLITE_OK;
    }

    private static long QueryFreeSpaceEstimate(IntPtr db)
    {
        long freelistCount = QuerySingleInt64(db, "PRAGMA freelist_count;");
        long pageSize = QuerySingleInt64(db, "PRAGMA page_size;");
        if (pageSize <= 0) pageSize = 4096;
        return Math.Max(0, freelistCount * pageSize);
    }

    private static long QuerySingleInt64(IntPtr db, string sql)
    {
        if (WinSqlite3.sqlite3_prepare_v2(db, sql, -1, out IntPtr stmt, IntPtr.Zero) != WinSqlite3.SQLITE_OK)
            return 0;
        try
        {
            if (WinSqlite3.sqlite3_step(stmt) == WinSqlite3.SQLITE_ROW)
                return WinSqlite3.sqlite3_column_int64(stmt, 0);
            return 0;
        }
        finally
        {
            WinSqlite3.sqlite3_finalize(stmt);
        }
    }

    private static bool IsSqliteHeader(string path)
    {
        try
        {
            Span<byte> header = stackalloc byte[16];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Read(header) < 16)
                return false;
            return header[..15].SequenceEqual("SQLite format 3"u8);
        }
        catch
        {
            return false;
        }
    }

    private static long GetSqliteFootprintBytes(string dbPath)
    {
        long total = 0;
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            var p = dbPath + suffix;
            try
            {
                if (File.Exists(p))
                    total += new FileInfo(p).Length;
            }
            catch { }
        }
        return total;
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = Math.Max(0, bytes);
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }

    private static class WinSqlite3
    {
        private const string DllName = "winsqlite3.dll";

        public const int SQLITE_OK = 0;
        public const int SQLITE_ROW = 100;
        public const int SQLITE_DONE = 101;

        public const int SQLITE_OPEN_READONLY = 0x00000001;
        public const int SQLITE_OPEN_READWRITE = 0x00000002;
        public const int SQLITE_OPEN_CREATE = 0x00000004;
        public const int SQLITE_OPEN_NOMUTEX = 0x00008000;

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_open_v2(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string filename,
            out IntPtr ppDb,
            int flags,
            IntPtr zVfs);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_close_v2(IntPtr db);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_busy_timeout(IntPtr db, int ms);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_exec(
            IntPtr db,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string sql,
            IntPtr callback,
            IntPtr arg,
            out IntPtr errmsg);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern void sqlite3_free(IntPtr ptr);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_prepare_v2(
            IntPtr db,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string zSql,
            int nByte,
            out IntPtr ppStmt,
            IntPtr pzTail);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_step(IntPtr pStmt);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern long sqlite3_column_int64(IntPtr pStmt, int iCol);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern IntPtr sqlite3_column_text(IntPtr pStmt, int iCol);

        [DllImport(DllName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        public static extern int sqlite3_finalize(IntPtr pStmt);
    }
}
