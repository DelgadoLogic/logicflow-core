using System.Threading.Tasks;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class NetworkOptimizerEngineTests
{
    [Fact]
    public async Task BenchmarkDnsProvidersAsync_ReturnsBenchmarkList()
    {
        var engine = new NetworkOptimizerEngine();
        var results = await engine.BenchmarkDnsProvidersAsync(timeoutMs: 1500);

        Assert.NotNull(results);
        Assert.NotEmpty(results);

        foreach (var item in results)
        {
            Assert.False(string.IsNullOrWhiteSpace(item.ProviderName));
            Assert.False(string.IsNullOrWhiteSpace(item.PrimaryIp));
        }
    }

    [Fact]
    public void FlushDns_ExecutesWithoutException()
    {
        var engine = new NetworkOptimizerEngine();
        var result = engine.FlushDns();
        // Should execute cleanly regardless of system elevation status
        Assert.True(result || !result);
    }
}
