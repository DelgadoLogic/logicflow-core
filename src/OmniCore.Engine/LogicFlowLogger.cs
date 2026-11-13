// OmniCore.Engine — Logging Infrastructure
// Proprietary implementation by DelgadoLogic.Tech

using Microsoft.Extensions.Logging;

namespace OmniCore.Engine;

/// <summary>
/// Lightweight structured logger for LogicFlow modules.
/// Writes to rotating log files in the application data directory.
/// </summary>
public sealed class LogicFlowLogger : IDisposable
{
    private readonly string _logDirectory;
    private readonly string _moduleName;
    private StreamWriter? _writer;
    private readonly object _writeLock = new();
    private long _currentFileSize;
    private const long MaxFileSize = 5 * 1024 * 1024; // 5MB rotation

    public LogicFlowLogger(string moduleName, string? logDirectory = null)
    {
        _moduleName = moduleName;
        _logDirectory = logDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow", "Logs");

        Directory.CreateDirectory(_logDirectory);
        OpenLogFile();
    }

    private void OpenLogFile()
    {
        var fileName = $"logicflow_{_moduleName}_{DateTime.UtcNow:yyyyMMdd}.log";
        var filePath = Path.Combine(_logDirectory, fileName);
        _writer = new StreamWriter(filePath, append: true) { AutoFlush = true };
        _currentFileSize = new FileInfo(filePath).Exists ? new FileInfo(filePath).Length : 0;
    }

    public void Log(LogLevel level, string message, params object?[] args)
    {
        var formattedMessage = args.Length > 0 ? string.Format(message, args) : message;
        var entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] [{level}] [{_moduleName}] {formattedMessage}";

        lock (_writeLock)
        {
            _writer?.WriteLine(entry);
            _currentFileSize += entry.Length + Environment.NewLine.Length;

            if (_currentFileSize >= MaxFileSize)
            {
                RotateLogFile();
            }
        }
    }

    public void Info(string message, params object?[] args) => Log(LogLevel.Information, message, args);
    public void Warn(string message, params object?[] args) => Log(LogLevel.Warning, message, args);
    public void Error(string message, params object?[] args) => Log(LogLevel.Error, message, args);
    public void Debug(string message, params object?[] args) => Log(LogLevel.Debug, message, args);

    private void RotateLogFile()
    {
        _writer?.Dispose();
        _currentFileSize = 0;
        OpenLogFile();
    }

    public void Dispose()
    {
        _writer?.Dispose();
    }
}

/// <summary>
/// Application-wide configuration for LogicFlow.
/// </summary>
public sealed class LogicFlowConfig
{
    public string AppDataPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LogicFlow");

    public string ResearchPath => Path.Combine(AppDataPath, "Research");
    public string LicensePath => Path.Combine(AppDataPath, "License");
    public string BackupPath => Path.Combine(AppDataPath, "Backups");
    public string CachePath => Path.Combine(AppDataPath, "Cache");

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(AppDataPath);
        Directory.CreateDirectory(ResearchPath);
        Directory.CreateDirectory(LicensePath);
        Directory.CreateDirectory(BackupPath);
        Directory.CreateDirectory(CachePath);
    }
}
