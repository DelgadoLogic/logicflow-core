using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogicFlow.Registry;
using Xunit;

namespace LogicFlow.Tests;

public class RegistrySurgeonTests
{
    [Fact]
    public void FormatBreakdown_WhenZeroIssues_ReturnsCleanSummary()
    {
        var result = new RegistryScanResult { TotalIssues = 0 };

        var breakdown = result.FormatBreakdown();

        Assert.Contains("100%", breakdown);
        Assert.Contains("0 issues", breakdown);
    }

    [Fact]
    public void FormatBreakdown_IncludesAllNonZeroCategories_SumEqualsTotal()
    {
        var result = new RegistryScanResult
        {
            OrphanedSoftwareKeys = [
                new() { Description = "O1", Path = "P1", Severity = IssueSeverity.Medium, IsSafeToFix = true },
                new() { Description = "O2", Path = "P2", Severity = IssueSeverity.Medium, IsSafeToFix = true },
                new() { Description = "O3", Path = "P3", Severity = IssueSeverity.Medium, IsSafeToFix = true },
                new() { Description = "O4", Path = "P4", Severity = IssueSeverity.Medium, IsSafeToFix = true },
            ],
            BrokenFileAssociations = Enumerable.Range(1, 14)
                .Select(i => new RegistryIssue { Description = $"BA{i}", Path = $"P{i}", Severity = IssueSeverity.Low, IsSafeToFix = true })
                .ToList(),
            InvalidPaths = [
                new() { Description = "IP1", Path = "P1", Severity = IssueSeverity.Low, IsSafeToFix = true }
            ],
            ObsoleteRunEntries = [
                new() { Description = "OR1", Path = "P1", Severity = IssueSeverity.Medium, IsSafeToFix = true },
                new() { Description = "OR2", Path = "P2", Severity = IssueSeverity.Medium, IsSafeToFix = true },
                new() { Description = "OR3", Path = "P3", Severity = IssueSeverity.Medium, IsSafeToFix = true },
            ],
            ComActiveXOrphans = Enumerable.Range(1, 300)
                .Select(i => new RegistryIssue { Description = $"COM{i}", Path = $"P{i}", Severity = IssueSeverity.Medium, IsSafeToFix = true })
                .ToList(),
            MuiCacheOrphans = Enumerable.Range(1, 259)
                .Select(i => new RegistryIssue { Description = $"MUI{i}", Path = $"P{i}", Severity = IssueSeverity.Low, IsSafeToFix = true })
                .ToList()
        };

        result.TotalIssues = result.OrphanedSoftwareKeys.Count +
                             result.BrokenFileAssociations.Count +
                             result.InvalidPaths.Count +
                             result.ObsoleteRunEntries.Count +
                             result.ComActiveXOrphans.Count +
                             result.SharedDllIssues.Count +
                             result.TypeLibOrphans.Count +
                             result.MuiCacheOrphans.Count +
                             result.HkcuOrphanedKeys.Count +
                             result.InstallerOrphans.Count;

        Assert.Equal(581, result.TotalIssues);

        var breakdown = result.FormatBreakdown();

        // Must display all contributing categories
        Assert.Contains("4 orphaned", breakdown);
        Assert.Contains("14 broken assoc", breakdown);
        Assert.Contains("1 invalid paths", breakdown);
        Assert.Contains("3 obsolete startup", breakdown);
        Assert.Contains("300 COM/ActiveX", breakdown);
        Assert.Contains("259 MUI cache", breakdown);
        Assert.EndsWith("= 581 total", breakdown);

        // Verify the mathematical sum of all category counts equals TotalIssues
        int sumOfCategories = result.CategorySummary.Values.Sum();
        Assert.Equal(result.TotalIssues, sumOfCategories);
    }

    [Fact]
    public void CalculateHealthScore_ZeroIssues_Returns100()
    {
        var result = new RegistryScanResult { TotalIssues = 0 };
        Assert.Equal(100, result.CalculateHealthScore());
    }

    [Fact]
    public void CalculateHealthScore_SingleLowIssue_Returns99()
    {
        var result = new RegistryScanResult
        {
            InvalidPaths = [
                new() { Description = "Test", Path = "Test", Severity = IssueSeverity.Low, IsSafeToFix = true }
            ]
        };
        result.TotalIssues = 1;

        Assert.Equal(99, result.CalculateHealthScore());
    }

    [Fact]
    public void CalculateHealthScore_581BenignIssues_DoesNotDropToZeroPercent()
    {
        // Realistic scenario: 581 total issues with mostly Low/Medium severity
        var result = new RegistryScanResult
        {
            OrphanedSoftwareKeys = Enumerable.Range(1, 4)
                .Select(i => new RegistryIssue { Description = $"O{i}", Path = "P", Severity = IssueSeverity.Medium, IsSafeToFix = true })
                .ToList(),
            BrokenFileAssociations = Enumerable.Range(1, 14)
                .Select(i => new RegistryIssue { Description = $"BA{i}", Path = "P", Severity = IssueSeverity.Low, IsSafeToFix = true })
                .ToList(),
            InvalidPaths = [
                new() { Description = "IP", Path = "P", Severity = IssueSeverity.Low, IsSafeToFix = true }
            ],
            ObsoleteRunEntries = Enumerable.Range(1, 3)
                .Select(i => new RegistryIssue { Description = $"OR{i}", Path = "P", Severity = IssueSeverity.Medium, IsSafeToFix = true })
                .ToList(),
            ComActiveXOrphans = Enumerable.Range(1, 300)
                .Select(i => new RegistryIssue { Description = $"COM{i}", Path = "P", Severity = IssueSeverity.Low, IsSafeToFix = true })
                .ToList(),
            MuiCacheOrphans = Enumerable.Range(1, 259)
                .Select(i => new RegistryIssue { Description = $"MUI{i}", Path = "P", Severity = IssueSeverity.Low, IsSafeToFix = true })
                .ToList()
        };

        result.TotalIssues = result.CategorySummary.Values.Sum();
        Assert.Equal(581, result.TotalIssues);

        int score = result.CalculateHealthScore();

        // Must NOT drop to 0% scareware
        Assert.InRange(score, 60, 85);
    }

    [Fact]
    public void CalculateHealthScore_CriticalIssues_DropsProportionately()
    {
        var result = new RegistryScanResult
        {
            OrphanedSoftwareKeys = Enumerable.Range(1, 8)
                .Select(i => new RegistryIssue { Description = $"Crit{i}", Path = "P", Severity = IssueSeverity.Critical, IsSafeToFix = true })
                .ToList()
        };
        result.TotalIssues = 8;

        int score = result.CalculateHealthScore();
        // 8 critical * 15 = 120 deduction -> 0
        Assert.Equal(0, score);
    }

    [Fact]
    public void SelectionAndSafeCounts_MatchExpectedItems()
    {
        var safeIssue = new RegistryIssue { Description = "Safe", Path = "P", IsSafeToFix = true, IsSelected = true };
        var riskyIssue = new RegistryIssue { Description = "Risky", Path = "P", IsSafeToFix = false, IsSelected = false };

        var result = new RegistryScanResult
        {
            OrphanedSoftwareKeys = [safeIssue],
            InstallerOrphans = [riskyIssue]
        };
        result.TotalIssues = 2;

        Assert.Equal(1, result.SafeToFixCount);
        Assert.Equal(1, result.SelectedCount);

        // Toggle selection
        safeIssue.IsSelected = false;
        Assert.Equal(0, result.SelectedCount);

        riskyIssue.IsSelected = true;
        Assert.Equal(1, result.SelectedCount);
    }

    [Fact]
    public void CategorySummary_ContainsAll10Categories()
    {
        var result = new RegistryScanResult();
        var summary = result.CategorySummary;

        Assert.Equal(10, summary.Count);
        Assert.True(summary.ContainsKey("Orphaned Software"));
        Assert.True(summary.ContainsKey("Broken File Associations"));
        Assert.True(summary.ContainsKey("Invalid App Paths"));
        Assert.True(summary.ContainsKey("Obsolete Startup Entries"));
        Assert.True(summary.ContainsKey("COM/ActiveX Orphans"));
        Assert.True(summary.ContainsKey("Missing Shared DLLs"));
        Assert.True(summary.ContainsKey("Type Library Orphans"));
        Assert.True(summary.ContainsKey("MUI Cache Orphans"));
        Assert.True(summary.ContainsKey("User Software Orphans"));
        Assert.True(summary.ContainsKey("Installer References"));
    }

    [Fact]
    public void TotalIssues_DynamicallyCalculatesSumOfPopulatedLists()
    {
        var result = new RegistryScanResult
        {
            OrphanedSoftwareKeys = [new() { Description = "O1", Path = "P1" }],
            BrokenFileAssociations = [new() { Description = "B1", Path = "P1" }, new() { Description = "B2", Path = "P2" }],
            InvalidPaths = [new() { Description = "I1", Path = "P1" }]
        };

        // Even without setting TotalIssues manually, it must calculate dynamically
        Assert.Equal(4, result.TotalIssues);

        result.ComActiveXOrphans.Add(new() { Description = "C1", Path = "P1" });
        Assert.Equal(5, result.TotalIssues);
    }

    [Fact]
    public void CalculateHealthScore_WhenListsNotPopulated_CalculatesProportionately()
    {
        var result = new RegistryScanResult { TotalIssues = 500 };
        int score = result.CalculateHealthScore();

        // Must calculate a realistic health score rather than arbitrarily returning 99% or 0%
        Assert.InRange(score, 60, 90);
    }

    [Fact]
    public void Fix_WhenInstallerOrphanSelectedAndOnlySafeFalse_DoesNotFilterOutTarget()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "LF_RegistryFix_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<RepairEngine>.Instance;
            var engine = new RepairEngine(logger, tempDir);

            var installerIssue = new RegistryIssue
            {
                Type = RegistryIssueType.InstallerOrphan,
                Path = @"HKLM\SOFTWARE\NonExistentTestProduct",
                FullRegistryPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\NonExistentTestProduct",
                Description = "Test installer product orphan",
                IsSafeToFix = false,
                IsSelected = true
            };

            // When onlySafe: true, it should correctly filter out the unsafe issue
            var safeResult = engine.Fix([installerIssue], onlySafe: true);
            Assert.Equal(0, safeResult.Fixed);
            Assert.Contains("No safe-to-fix", safeResult.Message);

            // When onlySafe: false, it must NOT drop the target issue before processing
            var fullResult = engine.Fix([installerIssue], onlySafe: false);
            // It will attempt the fix and either succeed or fail gracefully (key doesn't exist so failed=1 or fixed=0)
            // But Message must NOT be "No repairable issues found."
            Assert.NotEqual("No repairable issues found.", fullResult.Message);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }

    [Fact]
    public void FormatBreakdown_AllTenCategoriesWithIssues_SumStrictlyMatchesTotal()
    {
        var result = new RegistryScanResult
        {
            OrphanedSoftwareKeys = [new() { Description = "O1" }],
            BrokenFileAssociations = [new() { Description = "BA1" }, new() { Description = "BA2" }],
            InvalidPaths = [new() { Description = "IP1" }],
            ObsoleteRunEntries = [new() { Description = "OR1" }],
            ComActiveXOrphans = [new() { Description = "COM1" }],
            SharedDllIssues = [new() { Description = "DLL1" }],
            TypeLibOrphans = [new() { Description = "TLB1" }],
            MuiCacheOrphans = [new() { Description = "MUI1" }],
            HkcuOrphanedKeys = [new() { Description = "USR1" }],
            InstallerOrphans = [new() { Description = "INS1" }]
        };

        Assert.Equal(11, result.TotalIssues);

        var breakdown = result.FormatBreakdown();

        Assert.Contains("1 orphaned", breakdown);
        Assert.Contains("2 broken assoc", breakdown);
        Assert.Contains("1 invalid paths", breakdown);
        Assert.Contains("1 obsolete startup", breakdown);
        Assert.Contains("1 COM/ActiveX", breakdown);
        Assert.Contains("1 shared DLLs", breakdown);
        Assert.Contains("1 type libs", breakdown);
        Assert.Contains("1 MUI cache", breakdown);
        Assert.Contains("1 user orphans", breakdown);
        Assert.Contains("1 installer refs", breakdown);
        Assert.EndsWith("= 11 total", breakdown);
    }

    [Fact]
    public void ExtractExePath_UnquotedPathWithSpaces_ResolvesCorrectPathInsteadOfTruncatingToCProgram()
    {
        var input = @"C:\Program Files\NonExistentApp\tool.exe --arg1 /flag";
        var resolved = RegistryAnalyzer.ExtractExePath(input);

        // Crucial bugfix: Must preserve full executable path, NEVER truncate to "C:\Program"
        Assert.Equal(@"C:\Program Files\NonExistentApp\tool.exe", resolved);
        Assert.NotEqual(@"C:\Program", resolved);
    }

    [Fact]
    public void ExtractExePath_SystemExecutableWithoutDirectory_ResolvesSystem32OrWindowsDirectory()
    {
        var resolved = RegistryAnalyzer.ExtractExePath("notepad.exe %1");

        // Must locate notepad.exe in system folder rather than returning dead relative path
        Assert.True(File.Exists(resolved), $"Resolved path '{resolved}' should exist on disk");
        Assert.Contains("notepad.exe", resolved, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExtractExePath_EnvironmentVariables_ExpandsCorrectly()
    {
        var resolved = RegistryAnalyzer.ExtractExePath(@"%SystemRoot%\System32\notepad.exe %1");

        Assert.True(File.Exists(resolved), $"Resolved path '{resolved}' should exist on disk");
        Assert.DoesNotContain("%SystemRoot%", resolved);
    }

    [Fact]
    public void IsProtectedPath_ProtectsCriticalBranchesAndRoots()
    {
        // Core roots
        Assert.True(RegistryAnalyzer.IsProtectedPath(@"HKEY_LOCAL_MACHINE\SOFTWARE"));
        Assert.True(RegistryAnalyzer.IsProtectedPath(@"HKLM\SOFTWARE"));
        Assert.True(RegistryAnalyzer.IsProtectedPath(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet"));
        Assert.True(RegistryAnalyzer.IsProtectedPath(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        Assert.True(RegistryAnalyzer.IsProtectedPath(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        Assert.True(RegistryAnalyzer.IsProtectedPath(@"HKCR\CLSID"));

        // Benign non-root subkey should be allowed
        Assert.False(RegistryAnalyzer.IsProtectedPath(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TestOrphanApp"));
    }

    [Fact]
    public void CreateBackup_ConsolidatesAndCreatesMasterRegFileOnDisk()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "LF_Backup_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<RepairEngine>.Instance;
            var engine = new RepairEngine(logger, tempDir);

            var backupFile = engine.CreateBackup("Test unit backup");

            // Must create the physical master file returned by CreateBackup
            Assert.True(File.Exists(backupFile), $"Master backup file '{backupFile}' must exist on disk");
            var content = File.ReadAllText(backupFile);
            Assert.Contains("Windows Registry Editor Version 5.00", content);

            // ListBackups must discover the created master backup
            var backups = engine.ListBackups();
            Assert.Contains(backups, b => b.FilePath == backupFile);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
