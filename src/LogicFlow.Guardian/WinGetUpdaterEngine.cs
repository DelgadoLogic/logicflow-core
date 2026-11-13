// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian – WinGetUpdaterEngine
// Universal Windows Package & Software Updater Engine
// Leverages Microsoft WinGet CLI for 1-click silent application updates.
// Proprietary implementation by DelgadoLogic.Tech
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian
{
    public sealed class WinGetPackage
    {
        public string Name { get; init; } = "";
        public string Id { get; init; } = "";
        public string CurrentVersion { get; init; } = "";
        public string AvailableVersion { get; init; } = "";
        public string Source { get; init; } = "";
        public bool IsSelected { get; set; } = true;
    }

    public sealed class WinGetUpgradeResult
    {
        public string PackageId { get; init; } = "";
        public bool Success { get; init; }
        public string Output { get; init; } = "";
        public string? ErrorMessage { get; init; }
    }

    public sealed class WinGetUpdaterEngine
    {
        private readonly ILogger<WinGetUpdaterEngine>? _logger;

        public WinGetUpdaterEngine(ILogger<WinGetUpdaterEngine>? logger = null)
        {
            _logger = logger;
        }

        public static bool IsWinGetInstalled()
        {
            try
            {
                using var p = new Process();
                p.StartInfo = new ProcessStartInfo
                {
                    FileName = "winget",
                    Arguments = "--version",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                p.Start();
                p.WaitForExit(3000);
                return p.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public async Task<List<WinGetPackage>> ScanUpgradableAppsAsync(CancellationToken ct = default)
        {
            var packages = new List<WinGetPackage>();
            if (!IsWinGetInstalled())
            {
                _logger?.LogWarning("WinGet is not available on this system.");
                return packages;
            }

            Process? p = null;
            try
            {
                p = new Process();
                p.StartInfo = new ProcessStartInfo
                {
                    FileName = "winget",
                    Arguments = "upgrade --include-unknown",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                p.Start();

                var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
                var stderrTask = p.StandardError.ReadToEndAsync(ct);

                await Task.WhenAll(stdoutTask, stderrTask);
                await p.WaitForExitAsync(ct);

                string output = await stdoutTask;
                packages = ParseWinGetUpgradeOutput(output);
                _logger?.LogInformation("Discovered {Count} upgradable packages via WinGet.", packages.Count);
            }
            catch (OperationCanceledException)
            {
                try { if (p != null && !p.HasExited) p.Kill(entireProcessTree: true); } catch { }
                _logger?.LogInformation("WinGet upgrade scan was cancelled.");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to query WinGet upgrade packages.");
            }
            finally
            {
                p?.Dispose();
            }

            return packages;
        }

        public static List<WinGetPackage> ParseWinGetUpgradeOutput(string output)
        {
            var list = new List<WinGetPackage>();
            if (string.IsNullOrWhiteSpace(output)) return list;

            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int headerIdx = -1;
            int separatorIdx = -1;

            for (int i = 0; i < lines.Length; i++)
            {
                var l = lines[i];
                if (l.Contains("Name") && l.Contains("Id") && l.Contains("Version") && l.Contains("Available"))
                {
                    headerIdx = i;
                }
                else if (headerIdx != -1 && l.Trim().StartsWith("-") && l.Contains("---"))
                {
                    separatorIdx = i;
                    break;
                }
            }

            if (separatorIdx == -1 || separatorIdx + 1 >= lines.Length)
            {
                return list;
            }

            string headerLine = lines[headerIdx];
            int idIdx = headerLine.IndexOf("Id", StringComparison.OrdinalIgnoreCase);
            int versionIdx = headerLine.IndexOf("Version", StringComparison.OrdinalIgnoreCase);
            int availableIdx = headerLine.IndexOf("Available", StringComparison.OrdinalIgnoreCase);
            int sourceIdx = headerLine.IndexOf("Source", StringComparison.OrdinalIgnoreCase);

            for (int i = separatorIdx + 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.Contains("upgrades available") || line.Contains("packages have version")) break;

                if (idIdx > 0 && versionIdx > idIdx)
                {
                    string name = line.Length >= idIdx ? line.Substring(0, idIdx).Trim() : line.Trim();
                    string id = line.Length > idIdx ? (line.Length >= versionIdx ? line.Substring(idIdx, versionIdx - idIdx).Trim() : line.Substring(idIdx).Trim()) : "";
                    
                    if (line.Length > versionIdx)
                    {
                        string remainder = line.Substring(versionIdx).Trim();
                        var vTokens = remainder.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (vTokens.Length >= 2)
                        {
                            string curVer = vTokens[0];
                            string availVer = vTokens[1];
                            string source = vTokens.Length > 2 ? vTokens[2] : "winget";

                            if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(availVer))
                            {
                                list.Add(new WinGetPackage
                                {
                                    Name = name,
                                    Id = id,
                                    CurrentVersion = curVer,
                                    AvailableVersion = availVer,
                                    Source = source
                                });
                                continue;
                            }
                        }
                    }
                }

                // Fallback token split
                var parts = Regex.Split(line.Trim(), @"\s{2,}");
                if (parts.Length >= 4)
                {
                    list.Add(new WinGetPackage
                    {
                        Name = parts[0].Trim(),
                        Id = parts[1].Trim(),
                        CurrentVersion = parts[2].Trim(),
                        AvailableVersion = parts[3].Trim(),
                        Source = parts.Length > 4 ? parts[4].Trim() : "winget"
                    });
                }
            }

            return list;
        }

        public async Task<WinGetUpgradeResult> UpgradePackageAsync(string packageId, CancellationToken ct = default)
        {
            Process? p = null;
            try
            {
                p = new Process();
                p.StartInfo = new ProcessStartInfo
                {
                    FileName = "winget",
                    Arguments = $"upgrade --id \"{packageId}\" --silent --accept-source-agreements --accept-package-agreements",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                p.Start();

                var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
                var stderrTask = p.StandardError.ReadToEndAsync(ct);

                await Task.WhenAll(stdoutTask, stderrTask);
                await p.WaitForExitAsync(ct);

                string stdout = await stdoutTask;
                string stderr = await stderrTask;

                bool success = p.ExitCode == 0;
                return new WinGetUpgradeResult
                {
                    PackageId = packageId,
                    Success = success,
                    Output = stdout,
                    ErrorMessage = success ? null : stderr
                };
            }
            catch (OperationCanceledException)
            {
                try { if (p != null && !p.HasExited) p.Kill(entireProcessTree: true); } catch { }
                return new WinGetUpgradeResult
                {
                    PackageId = packageId,
                    Success = false,
                    ErrorMessage = "Operation was cancelled."
                };
            }
            catch (Exception ex)
            {
                return new WinGetUpgradeResult
                {
                    PackageId = packageId,
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
            finally
            {
                p?.Dispose();
            }
        }

        public async Task<WinGetUpgradeResult> UpgradeAllAsync(CancellationToken ct = default)
        {
            Process? p = null;
            try
            {
                p = new Process();
                p.StartInfo = new ProcessStartInfo
                {
                    FileName = "winget",
                    Arguments = "upgrade --all --silent --accept-source-agreements --accept-package-agreements",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                p.Start();

                var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
                var stderrTask = p.StandardError.ReadToEndAsync(ct);

                await Task.WhenAll(stdoutTask, stderrTask);
                await p.WaitForExitAsync(ct);

                string stdout = await stdoutTask;
                string stderr = await stderrTask;

                bool success = p.ExitCode == 0;
                return new WinGetUpgradeResult
                {
                    PackageId = "ALL",
                    Success = success,
                    Output = stdout,
                    ErrorMessage = success ? null : stderr
                };
            }
            catch (OperationCanceledException)
            {
                try { if (p != null && !p.HasExited) p.Kill(entireProcessTree: true); } catch { }
                return new WinGetUpgradeResult
                {
                    PackageId = "ALL",
                    Success = false,
                    ErrorMessage = "Operation was cancelled."
                };
            }
            catch (Exception ex)
            {
                return new WinGetUpgradeResult
                {
                    PackageId = "ALL",
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
            finally
            {
                p?.Dispose();
            }
        }

        public async Task<List<WinGetUpgradeResult>> UpgradePackagesAsync(IEnumerable<string> packageIds, CancellationToken ct = default)
        {
            var results = new List<WinGetUpgradeResult>();
            foreach (var id in packageIds)
            {
                if (ct.IsCancellationRequested) break;
                var res = await UpgradePackageAsync(id, ct);
                results.Add(res);
            }
            return results;
        }
    }
}
