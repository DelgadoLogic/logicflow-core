using System.Collections.Generic;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class SmartDiskHealthTests
{
    [Theory]
    [InlineData(-1, "N/A")]
    [InlineData(-10, "N/A")]
    [InlineData(95, "A+")]
    [InlineData(90, "A+")]
    [InlineData(85, "A")]
    [InlineData(80, "A")]
    [InlineData(75, "B")]
    [InlineData(70, "B")]
    [InlineData(65, "C")]
    [InlineData(60, "C")]
    [InlineData(50, "D")]
    [InlineData(40, "D")]
    [InlineData(25, "F")]
    [InlineData(0, "F")]
    public void DiskSmartReport_HealthGrade_MapsCorrectly(int score, string expectedGrade)
    {
        var report = new SmartDiskHealth.DiskSmartReport
        {
            HealthScore = score,
            Status = score >= 0 ? SmartDiskHealth.DiskHealthStatus.Healthy : SmartDiskHealth.DiskHealthStatus.Unknown
        };

        Assert.Equal(expectedGrade, report.HealthGrade);
    }

    [Theory]
    [InlineData(0, "N/A")]
    [InlineData(-5, "N/A")]
    [InlineData(12, "12h")]
    [InlineData(25, "1d 1h")]
    [InlineData(720, "1mo")]
    [InlineData(8760, "1yr")]
    public void DiskSmartReport_PowerOnFormatted_HandlesUnmeasuredAndHours(long hours, string expected)
    {
        var report = new SmartDiskHealth.DiskSmartReport
        {
            PowerOnHours = hours
        };

        Assert.Equal(expected, report.PowerOnFormatted);
    }

    [Fact]
    public void DiskSmartReport_TotalWrittenFormatted_HandlesZeroAndPositive()
    {
        var zeroReport = new SmartDiskHealth.DiskSmartReport { TotalBytesWritten = 0 };
        Assert.Equal("N/A", zeroReport.TotalWrittenFormatted);

        var positiveReport = new SmartDiskHealth.DiskSmartReport { TotalBytesWritten = 1024L * 1024 * 1024 * 100 };
        Assert.Contains("GB", positiveReport.TotalWrittenFormatted);
    }

    [Fact]
    public void ScanDrives_ExecutesSafelyAndReturnsReports()
    {
        var scanner = new SmartDiskHealth();
        var reports = scanner.ScanDrives();

        Assert.NotNull(reports);
        foreach (var report in reports)
        {
            Assert.NotNull(report.Model);
            // Verify temperature classification: if unmeasured (<= 0), status must be Unknown
            if (report.Temperature <= 0)
            {
                Assert.Equal(SmartDiskHealth.TemperatureStatus.Unknown, report.TempStatus);
            }
            else
            {
                Assert.NotEqual(SmartDiskHealth.TemperatureStatus.Unknown, report.TempStatus);
            }

            // Verify health score and grade consistency
            if (report.HealthScore < 0)
            {
                Assert.Equal("N/A", report.HealthGrade);
            }
            else
            {
                Assert.NotEqual("N/A", report.HealthGrade);
            }
        }
    }

    [Fact]
    public void TryGetNvmeHealthInfo_CanBeCalledWithoutException()
    {
        var info = SmartDiskHealth.TryGetNvmeHealthInfo(0);
        // On machine with NVMe, it may return data or null if non-admin/unsupported, but must never throw
        if (info != null)
        {
            Assert.True(info.TemperatureCelsius >= 0);
            Assert.True(info.PercentageUsed >= -1);
        }
    }

    [Fact]
    public void ParseCachedDiskSummaryFromJson_PrioritizesModelMatchOverIndex()
    {
        string json = @"
        {
            ""DiskHealthSummary"": [
                {
                    ""Model"": ""Crucial P3 CT1000P3SSD8"",
                    ""HealthScore"": 92,
                    ""Status"": ""Healthy"",
                    ""SizeGB"": 1000.0,
                    ""Temperature"": 38,
                    ""SsdLifeRemaining"": 95,
                    ""PowerOnHours"": 1200
                },
                {
                    ""Model"": ""Samsung SSD 980 PRO 1TB"",
                    ""HealthScore"": 98,
                    ""Status"": ""Healthy"",
                    ""SizeGB"": 1000.0,
                    ""Temperature"": 42,
                    ""SsdLifeRemaining"": 99,
                    ""PowerOnHours"": 3400
                }
            ]
        }";

        // Even though diskIndex is 0, model is Samsung 980 PRO — it must match Samsung (disk 1), NOT Crucial!
        var match = SmartDiskHealth.ParseCachedDiskSummaryFromJson(json, "Samsung SSD 980 PRO", 0);
        Assert.NotNull(match);
        Assert.Equal("Samsung SSD 980 PRO 1TB", match.Model);
        Assert.Equal(98, match.HealthScore);
        Assert.Equal(42, match.Temperature);
        Assert.Equal(99, match.SsdLifeRemaining);
    }

    [Fact]
    public void ParseCachedDiskSummaryFromJson_FallsBackToIndexWhenModelEmpty()
    {
        string json = @"
        {
            ""DiskHealthSummary"": [
                {
                    ""Model"": ""Drive Zero"",
                    ""HealthScore"": 85,
                    ""Status"": ""Healthy"",
                    ""SizeGB"": 512.0,
                    ""Temperature"": 35,
                    ""SsdLifeRemaining"": 90,
                    ""PowerOnHours"": 500
                },
                {
                    ""Model"": ""Drive One"",
                    ""HealthScore"": 95,
                    ""Status"": ""Healthy"",
                    ""SizeGB"": 1024.0,
                    ""Temperature"": 40,
                    ""SsdLifeRemaining"": 96,
                    ""PowerOnHours"": 1500
                }
            ]
        }";

        var match0 = SmartDiskHealth.ParseCachedDiskSummaryFromJson(json, "", 0);
        Assert.NotNull(match0);
        Assert.Equal("Drive Zero", match0.Model);

        var match1 = SmartDiskHealth.ParseCachedDiskSummaryFromJson(json, "Unknown Drive", 1);
        Assert.NotNull(match1);
        Assert.Equal("Drive One", match1.Model);
    }

    [Fact]
    public void BuildHealthSummary_HandlesUnmeasuredAndCachedAgentNotice()
    {
        var summary = SmartDiskHealth.BuildHealthSummary(
            SmartDiskHealth.DiskHealthStatus.Healthy,
            95,
            reallocated: 0,
            pending: 0,
            temp: 45,
            tempStatus: SmartDiskHealth.TemperatureStatus.Normal,
            ssdLifeRemaining: 98,
            nvmePercentUsed: 2,
            operStatus: "OK",
            isSsd: true,
            fromCachedAgent: true);

        Assert.Contains("S.M.A.R.T. telemetry synchronized from elevated LogicFlow Agent", summary);
        Assert.Contains("95%", summary);
        Assert.Contains("45°C", summary);
        Assert.Contains("SSD life remaining: 98%", summary);
    }
}
