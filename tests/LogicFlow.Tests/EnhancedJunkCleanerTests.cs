// LogicFlow.Tests — EnhancedJunkCleanerTests
// Tests for GPU Shader Caches, DriverStore, and Delivery Optimization junk scanning.

using System.Linq;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class EnhancedJunkCleanerTests
{
    [Fact]
    public void Scan_IncludesNewCategories()
    {
        var cleaner = new JunkCleanerEngine();
        var results = cleaner.Scan();

        Assert.NotNull(results);
        Assert.Contains(results, r => r.Category == JunkCleanerEngine.JunkCategory.GpuShaderCache);
        Assert.Contains(results, r => r.Category == JunkCleanerEngine.JunkCategory.DriverStoreCache);
        Assert.Contains(results, r => r.Category == JunkCleanerEngine.JunkCategory.DeliveryOptimizationCache);
        Assert.Contains(results, r => r.Category == JunkCleanerEngine.JunkCategory.RecycleBin);
    }

    [Fact]
    public void Scan_CalculatesMetricsCorrectly()
    {
        var cleaner = new JunkCleanerEngine();
        var results = cleaner.Scan();

        foreach (var r in results)
        {
            Assert.True(r.TotalBytes >= 0);
            Assert.True(r.FileCount >= 0);
            Assert.False(string.IsNullOrWhiteSpace(r.DisplayName));
            Assert.False(string.IsNullOrWhiteSpace(r.Description));
        }
    }

    [Fact]
    public void SHQUERYRBINFO_StructSize_MatchesNativeShell32Alignment()
    {
        int size = System.Runtime.InteropServices.Marshal.SizeOf<JunkCleanerEngine.SHQUERYRBINFO>();
        // On 64-bit systems, native shell32 SHQUERYRBINFO is 24 bytes (4 bytes cbSize + 4 bytes padding + 8 bytes i64Size + 8 bytes i64NumItems)
        if (System.IntPtr.Size == 8)
        {
            Assert.Equal(24, size);
        }
        else
        {
            Assert.Equal(20, size);
        }
    }

    [Fact]
    public void Clean_WithRecycleBinCategory_CompletesSafely()
    {
        var cleaner = new JunkCleanerEngine();
        var results = cleaner.Scan();
        var rbCategory = results.FirstOrDefault(r => r.Category == JunkCleanerEngine.JunkCategory.RecycleBin);
        Assert.NotNull(rbCategory);

        rbCategory.IsSelected = true;
        var cleanResult = cleaner.Clean(new System.Collections.Generic.List<JunkCleanerEngine.JunkScanResult> { rbCategory });

        Assert.NotNull(cleanResult);
        Assert.True(cleanResult.BytesCleaned >= 0);
        Assert.True(cleanResult.FilesDeleted >= 0);
    }
}
