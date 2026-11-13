using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using LogicFlow.CLI.Framework;
using LogicFlow.Lazarus;

namespace LogicFlow.CLI.Commands
{
    public static class LazarusCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command.ToLowerInvariant())
            {
                case "drives":
                    return HandleDrives(ctx);
                case "mtp":
                    return HandleMtp(ctx);
                case "carve":
                    return HandleCarve(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown lazarus command: '{command}'. Available: drives, mtp, carve", new { error = "UNKNOWN_COMMAND", group = "lazarus", command });
                    return 1;
            }
        }

        private static int HandleDrives(CliContext ctx)
        {
            try
            {
                var physicalDrives = new List<object>();
                bool anyRawAccess = false;

                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT DeviceID, Index, Model, InterfaceType, Size, Status, MediaType FROM Win32_DiskDrive");
                    foreach (var obj in searcher.Get())
                    {
                        var devId = obj["DeviceID"]?.ToString() ?? "";
                        var model = obj["Model"]?.ToString() ?? "Generic Disk";
                        var iface = obj["InterfaceType"]?.ToString() ?? "Unknown";
                        var status = obj["Status"]?.ToString() ?? "OK";
                        var mediaType = obj["MediaType"]?.ToString() ?? "";
                        long size = 0;
                        if (obj["Size"] != null)
                        {
                            long.TryParse(obj["Size"]?.ToString(), out size);
                        }

                        int driveIndex = -1;
                        if (obj["Index"] != null)
                        {
                            int.TryParse(obj["Index"]?.ToString(), out driveIndex);
                        }

                        bool rawAccessible = false;
                        if (driveIndex >= 0)
                        {
                            using var scanner = new SectorScanner(Microsoft.Extensions.Logging.Abstractions.NullLogger<SectorScanner>.Instance);
                            rawAccessible = scanner.OpenDrive(driveIndex);
                            if (rawAccessible) anyRawAccess = true;
                        }

                        physicalDrives.Add(new
                        {
                            deviceId = devId,
                            index = driveIndex,
                            model,
                            interfaceType = iface,
                            mediaType,
                            sizeBytes = size,
                            sizeFormatted = FormatBytes(size),
                            status,
                            rawSectorAccess = rawAccessible
                        });
                    }
                }
                catch
                {
                    // Fallback if WMI query is restricted
                }

                var logicalVolumes = new List<object>();
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
                {
                    logicalVolumes.Add(new
                    {
                        name = drive.Name,
                        label = string.IsNullOrEmpty(drive.VolumeLabel) ? "(No label)" : drive.VolumeLabel,
                        driveType = drive.DriveType.ToString(),
                        format = drive.DriveFormat,
                        totalSizeBytes = drive.TotalSize,
                        totalSizeFormatted = FormatBytes(drive.TotalSize),
                        freeSpaceBytes = drive.TotalFreeSpace,
                        freeSpaceFormatted = FormatBytes(drive.TotalFreeSpace)
                    });
                }

                var payload = new
                {
                    status = "SCANNED",
                    totalPhysicalDrives = physicalDrives.Count,
                    totalLogicalVolumes = logicalVolumes.Count,
                    rawSectorRecoveryReady = anyRawAccess,
                    physicalDrives,
                    logicalVolumes
                };

                OutputFormatter.Write(ctx, $"[LAZARUS] Found {physicalDrives.Count} physical drive(s) and {logicalVolumes.Count} mounted volume(s). Raw sector access: {(anyRawAccess ? "AVAILABLE" : "RESTRICTED (Run as Administrator)")}", payload, anyRawAccess ? ConsoleColor.Green : ConsoleColor.Yellow);

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    if (physicalDrives.Count > 0)
                    {
                        Console.WriteLine("\n  Physical Disks:");
                        foreach (dynamic p in physicalDrives)
                        {
                            var rawTag = p.rawSectorAccess ? "[RAW ACTIVE]" : "[ACCESS DENIED]";
                            var col = p.rawSectorAccess ? ConsoleColor.Green : ConsoleColor.DarkGray;
                            Console.ForegroundColor = col;
                            Console.WriteLine($"    {rawTag,-15} PhysicalDrive{p.index,-3} {p.model,-35} {p.sizeFormatted,-10} ({p.interfaceType})");
                            Console.ResetColor();
                        }
                    }

                    if (logicalVolumes.Count > 0)
                    {
                        Console.WriteLine("\n  Mounted Volumes:");
                        foreach (dynamic v in logicalVolumes)
                        {
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"    {v.name,-6} {v.label,-20} {v.format,-8} {v.freeSpaceFormatted} free / {v.totalSizeFormatted} total");
                            Console.ResetColor();
                        }
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to scan drives: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleMtp(CliContext ctx)
        {
            try
            {
                var bridge = new MtpBridge(Microsoft.Extensions.Logging.Abstractions.NullLogger<MtpBridge>.Instance);
                var devices = bridge.EnumerateDevices();

                var payload = new
                {
                    status = "SCANNED",
                    count = devices.Count,
                    devices = devices.Select(d => new
                    {
                        name = d.Name,
                        deviceId = d.DeviceId,
                        manufacturer = d.Manufacturer,
                        status = d.Status
                    }).ToList()
                };

                if (devices.Count == 0)
                {
                    OutputFormatter.Write(ctx, "[LAZARUS] No connected MTP / portable storage devices detected.", payload, ConsoleColor.Yellow);
                    return 0;
                }

                OutputFormatter.Write(ctx, $"[LAZARUS] Found {devices.Count} connected MTP / portable device(s):", payload, ConsoleColor.Green);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var d in devices)
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"  * {d.Name,-30} ({d.Manufacturer}) — Status: {d.Status}");
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"    DeviceID: {d.DeviceId}");
                        Console.ResetColor();
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to scan MTP devices: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleCarve(CliContext ctx)
        {
            try
            {
                int driveIndex = 0;
                long sectorsToScan = 2048; // 1 MB default for responsive CLI carving

                for (int i = 0; i < ctx.RemainingArgs.Length; i++)
                {
                    string a = ctx.RemainingArgs[i];
                    if (a.Equals("--drive", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        int.TryParse(ctx.RemainingArgs[++i], out driveIndex);
                    }
                    else if (a.Equals("--sectors", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        long.TryParse(ctx.RemainingArgs[++i], out sectorsToScan);
                    }
                    else if (int.TryParse(a, out int parsedIndex) && !a.StartsWith("-") && !a.Equals("carve", StringComparison.OrdinalIgnoreCase) && !a.Equals("lazarus", StringComparison.OrdinalIgnoreCase))
                    {
                        driveIndex = parsedIndex;
                    }
                }

                using var scanner = new SectorScanner(Microsoft.Extensions.Logging.Abstractions.NullLogger<SectorScanner>.Instance);
                bool opened = scanner.OpenDrive(driveIndex);
                if (!opened)
                {
                    OutputFormatter.WriteError(ctx, $"Failed to open PhysicalDrive{driveIndex} for raw sector carving. Administrator privileges required.", new { status = "ACCESS_DENIED", driveIndex, requiresAdmin = true });
                    return 1;
                }

                OutputFormatter.Write(ctx, $"[LAZARUS] Carving PhysicalDrive{driveIndex} across {sectorsToScan:N0} sectors for file signatures...", null, ConsoleColor.Yellow);

                var carver = new FileCarver(Microsoft.Extensions.Logging.Abstractions.NullLogger<FileCarver>.Instance);
                var allFound = new List<CarvedFileHeader>();
                const int chunkSize = 64; // 64 sectors (32 KB) per chunk
                byte[] chunkBuffer = new byte[chunkSize * 512];

                for (long sec = 0; sec < sectorsToScan; sec += chunkSize)
                {
                    int sectorsToRead = (int)Math.Min(chunkSize, sectorsToScan - sec);
                    int bytesFilled = 0;

                    for (int s = 0; s < sectorsToRead; s++)
                    {
                        var secData = scanner.ReadSector(sec + s);
                        if (secData != null && secData.Length == 512)
                        {
                            Array.Copy(secData, 0, chunkBuffer, s * 512, 512);
                            bytesFilled += 512;
                        }
                    }

                    if (bytesFilled > 0)
                    {
                        var headers = carver.ScanBuffer(chunkBuffer.AsSpan(0, bytesFilled), sec * 512);
                        allFound.AddRange(headers);
                    }
                }

                var payload = new
                {
                    status = "CARVE_COMPLETE",
                    driveIndex,
                    sectorsScanned = sectorsToScan,
                    bytesScanned = sectorsToScan * 512,
                    foundCount = allFound.Count,
                    signatures = allFound.Select(f => new
                    {
                        extension = f.Extension,
                        fileType = f.FileType,
                        byteOffset = f.ByteOffset
                    }).ToList()
                };

                OutputFormatter.Write(ctx, $"[LAZARUS] Carve complete on PhysicalDrive{driveIndex}. Scanned {sectorsToScan:N0} sectors ({sectorsToScan * 512 / 1024} KB). Found {allFound.Count} file signature(s).", payload, ConsoleColor.Green);
                if (!ctx.IsJson && !ctx.IsSilent && allFound.Count > 0)
                {
                    foreach (var f in allFound.Take(20))
                    {
                        Console.WriteLine($"  * [{f.Extension.ToUpperInvariant()}] {f.FileType} found at byte offset 0x{f.ByteOffset:X8}");
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Carve failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
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
}
