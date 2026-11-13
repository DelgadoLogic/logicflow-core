// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests – PagefileOptimizerTests
// Unit tests for PagefileOptimizer sizing logic, disk space safety bounds,
// external USB exclusion, and optimal drive selection.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests
{
    public class PagefileOptimizerTests
    {
        [Fact]
        public void CalculateOptimalSize_LowRam_ScalesAggressively()
        {
            // 4 GB RAM, ample disk space
            long ramMB = 4096;
            var targetDrive = new PagefileOptimizer.DriveAnalysis
            {
                DriveLetter = "C",
                FreeSpaceGB = 100,
                TotalSpaceGB = 500,
                IsSsd = true,
                IsSystemDrive = true
            };

            var (initialMB, maxMB, rationale) = PagefileOptimizer.CalculateOptimalSize(ramMB, 2000, 8000, targetDrive);

            // 1.5x initial (6144), 2.5x max (10240)
            Assert.Equal(6144, initialMB);
            Assert.Equal(10240, maxMB);
            Assert.Contains("Low-capacity RAM", rationale);
        }

        [Theory]
        [InlineData(49152)] // 48 GB RAM
        [InlineData(65536)] // 64 GB RAM
        [InlineData(131072)] // 128 GB RAM
        public void CalculateOptimalSize_HighCapacityRam_CapsConservativelyForCrashDump(long ramMB)
        {
            var targetDrive = new PagefileOptimizer.DriveAnalysis
            {
                DriveLetter = "C",
                FreeSpaceGB = 200,
                TotalSpaceGB = 1000,
                IsSsd = true,
                IsSystemDrive = true
            };

            var (initialMB, maxMB, rationale) = PagefileOptimizer.CalculateOptimalSize(ramMB, 8000, 70000, targetDrive);

            // High RAM systems (>32GB) must not allocate massive 32-64GB pagefiles; 8-16 GB is optimal for BSOD crash dumps
            Assert.Equal(8192, initialMB);
            Assert.Equal(16384, maxMB);
            Assert.Contains("High-capacity RAM", rationale);
            Assert.Contains("BSOD", rationale);
        }

        [Fact]
        public void CalculateOptimalSize_LowDiskSpace_CapsAt45PercentTargetFreeSpace()
        {
            // System has 32 GB RAM (32768 MB) which normally recommends up to 16384 MB (16 GB),
            // BUT target drive C: only has 22 GB free space (22528 MB).
            // Safe max cap is 45% of 22 GB = ~10137 MB.
            long ramMB = 32768;
            var targetDrive = new PagefileOptimizer.DriveAnalysis
            {
                DriveLetter = "C",
                FreeSpaceGB = 22,
                TotalSpaceGB = 512,
                IsSsd = true,
                IsSystemDrive = true
            };

            var (initialMB, maxMB, rationale) = PagefileOptimizer.CalculateOptimalSize(ramMB, 12000, 34000, targetDrive);

            long maxAllowedCapMB = (long)(22 * 1024 * 0.45);
            Assert.True(maxMB <= maxAllowedCapMB, $"maxMB ({maxMB}) should not exceed 45% of free space ({maxAllowedCapMB})");
            Assert.True(initialMB <= maxMB, "initialMB must not exceed maxMB");
            Assert.Contains("Conservatively capped", rationale);
            Assert.Contains("22 GB available", rationale);
        }

        [Fact]
        public void CalculateOptimalSize_ExtremelyLowFreeSpace_NeverExceeds45PercentCap()
        {
            // System has 16 GB RAM, but target drive C: only has 2 GB free (2048 MB).
            // Safe max cap is 45% of 2 GB = 921 MB.
            long ramMB = 16384;
            var targetDrive = new PagefileOptimizer.DriveAnalysis
            {
                DriveLetter = "C",
                FreeSpaceGB = 2,
                TotalSpaceGB = 64,
                IsSsd = true,
                IsSystemDrive = true
            };

            var (initialMB, maxMB, rationale) = PagefileOptimizer.CalculateOptimalSize(ramMB, 8000, 16000, targetDrive);

            long maxAllowedCapMB = (long)(2 * 1024 * 0.45);
            Assert.True(maxMB <= maxAllowedCapMB, $"maxMB ({maxMB}) must never exceed 45% of free space ({maxAllowedCapMB})");
            Assert.True(initialMB <= maxMB, "initialMB must not exceed maxMB");
            Assert.Contains("Conservatively capped", rationale);
        }

        [Fact]
        public void CalculateOptimalSize_HighCommitHeadroom_ExpandsSafely()
        {
            long ramMB = 16384;
            // High commit load (32 GB committed on 16 GB RAM with 100 GB disk headroom)
            long commitChargeMB = 32000;
            long commitLimitMB = 34000;
            var targetDrive = new PagefileOptimizer.DriveAnalysis
            {
                DriveLetter = "C",
                FreeSpaceGB = 100,
                TotalSpaceGB = 500,
                IsSsd = true,
                IsSystemDrive = true
            };

            var (initialMB, maxMB, _) = PagefileOptimizer.CalculateOptimalSize(ramMB, commitChargeMB, commitLimitMB, targetDrive);

            // Peak need is 32000 * 1.25 = 40000; 40000 - 16384 = 23616 MB > 16384 MB
            Assert.True(maxMB >= 23616, $"maxMB ({maxMB}) should expand to accommodate high active commit");
        }

        [Fact]
        public void SelectOptimalDrive_ExcludesExternalUsbDrives_EvenWithMassiveSpace()
        {
            var drives = new List<PagefileOptimizer.DriveAnalysis>
            {
                new()
                {
                    DriveLetter = "C",
                    IsSystemDrive = true,
                    IsSsd = true,
                    IsExternal = false,
                    BusType = "NVMe",
                    FreeSpaceGB = 25,
                    TotalSpaceGB = 512,
                    MediaType = "SSD"
                },
                new()
                {
                    DriveLetter = "D",
                    IsSystemDrive = false,
                    IsSsd = true,
                    IsExternal = true,
                    BusType = "USB",
                    FreeSpaceGB = 1800,
                    TotalSpaceGB = 2000,
                    MediaType = "USB-SSD"
                }
            };

            var selected = PagefileOptimizer.SelectOptimalDrive(drives);

            Assert.NotNull(selected);
            Assert.Equal("C", selected!.DriveLetter);
            Assert.False(selected.IsExternal);
            Assert.NotEqual("USB", selected.BusType);
        }

        [Fact]
        public void SelectOptimalDrive_WithConstrainedSystemDrive_PrefersInternalSecondarySsdOverUsb()
        {
            var drives = new List<PagefileOptimizer.DriveAnalysis>
            {
                new()
                {
                    DriveLetter = "C",
                    IsSystemDrive = true,
                    IsSsd = true,
                    IsExternal = false,
                    BusType = "NVMe",
                    FreeSpaceGB = 8, // Constrained (<15 GB)
                    TotalSpaceGB = 256,
                    MediaType = "SSD"
                },
                new()
                {
                    DriveLetter = "D",
                    IsSystemDrive = false,
                    IsSsd = true,
                    IsExternal = true,
                    BusType = "USB",
                    FreeSpaceGB = 2000,
                    TotalSpaceGB = 2000,
                    MediaType = "USB-SSD"
                },
                new()
                {
                    DriveLetter = "E",
                    IsSystemDrive = false,
                    IsSsd = true,
                    IsExternal = false,
                    BusType = "NVMe",
                    FreeSpaceGB = 150, // Internal SSD with ample space (>=30 GB)
                    TotalSpaceGB = 1000,
                    MediaType = "SSD"
                }
            };

            var selected = PagefileOptimizer.SelectOptimalDrive(drives);

            Assert.NotNull(selected);
            // Drive E is selected because C is space-constrained and D is an excluded USB drive
            Assert.Equal("E", selected!.DriveLetter);
        }

        [Fact]
        public void SelectOptimalDrive_WhenBootDriveHas22GBFreeAndSecondarySsdHas280GBFree_PrefersSecondarySsd()
        {
            // Exact user scenario: Boot drive C has 22 GB free space (<30 GB threshold),
            // while internal secondary NVMe SSD D has 280 GB free space.
            var drives = new List<PagefileOptimizer.DriveAnalysis>
            {
                new()
                {
                    DriveLetter = "C",
                    IsSystemDrive = true,
                    IsSsd = true,
                    IsExternal = false,
                    BusType = "NVMe",
                    FreeSpaceGB = 22,
                    TotalSpaceGB = 512,
                    MediaType = "SSD"
                },
                new()
                {
                    DriveLetter = "D",
                    IsSystemDrive = false,
                    IsSsd = true,
                    IsExternal = false,
                    BusType = "NVMe",
                    FreeSpaceGB = 280,
                    TotalSpaceGB = 1000,
                    MediaType = "SSD"
                }
            };

            var selected = PagefileOptimizer.SelectOptimalDrive(drives);

            Assert.NotNull(selected);
            Assert.Equal("D", selected!.DriveLetter);
            Assert.Equal(280, selected.FreeSpaceGB);
        }

        [Fact]
        public void SelectOptimalDrive_EmptyOrNullList_ReturnsNull()
        {
            Assert.Null(PagefileOptimizer.SelectOptimalDrive(null!));
            Assert.Null(PagefileOptimizer.SelectOptimalDrive(new List<PagefileOptimizer.DriveAnalysis>()));
        }

        [Fact]
        public void MemoryBreakdown_PercentageAndFormatting_AreValid()
        {
            var breakdown = new MemoryOptimizer.MemoryBreakdown
            {
                TotalPhysicalBytes = 32L * 1024 * 1024 * 1024, // 32 GB
                InUseBytes = 16L * 1024 * 1024 * 1024,         // 16 GB
                StandbyCacheBytes = 8L * 1024 * 1024 * 1024,   // 8 GB
                FreeBytes = 8L * 1024 * 1024 * 1024,           // 8 GB
                CommittedBytes = 20L * 1024 * 1024 * 1024,     // 20 GB
                CommitLimitBytes = 36L * 1024 * 1024 * 1024    // 36 GB
            };

            Assert.Equal(50.0, breakdown.InUsePercent);
            Assert.Equal(25.0, breakdown.StandbyPercent);
            Assert.Equal(25.0, breakdown.FreePercent);
            Assert.True(breakdown.CommitPercent > 0);

            Assert.NotEmpty(breakdown.TotalFormatted);
            Assert.NotEmpty(breakdown.InUseFormatted);
            Assert.NotEmpty(breakdown.StandbyFormatted);
            Assert.NotEmpty(breakdown.FreeFormatted);
        }
    }
}
