// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests – SecurityCommandsTests
// Unit test suite for CLI SecurityCommands and CliContext routing.
// Validates defender-harden, persistence-audit, hosts-check, --json formatting,
// subcommand delegation, and exit code handling.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Xunit;

namespace LogicFlow.Tests
{
    [Collection("CliConsoleExecution")]
    public class SecurityCommandsTests
    {
        private static readonly Assembly CliAssembly = LoadCliAssembly();
        private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
        private static readonly Type SecurityCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.SecurityCommands")!;

        private static Assembly LoadCliAssembly()
        {
            try
            {
                return Assembly.Load("lf");
            }
            catch
            {
                var dir = new DirectoryInfo(AppContext.BaseDirectory);
                while (dir != null)
                {
                    string cliRel = Path.Combine(dir.FullName, "src", "LogicFlow.CLI", "bin", "Release", "net8.0-windows", "lf.dll");
                    if (File.Exists(cliRel)) return Assembly.LoadFrom(cliRel);

                    string cliDebug = Path.Combine(dir.FullName, "src", "LogicFlow.CLI", "bin", "Debug", "net8.0-windows", "lf.dll");
                    if (File.Exists(cliDebug)) return Assembly.LoadFrom(cliDebug);

                    dir = dir.Parent;
                }

                throw new InvalidOperationException($"Could not find lf.dll assembly for testing. BaseDirectory: {AppContext.BaseDirectory}");
            }
        }

        private object CreateCliContext(bool isJson = false, bool isForce = false, bool isSilent = false, params string[] args)
        {
            var ctx = Activator.CreateInstance(CliContextType)!;
            CliContextType.GetProperty("IsJson")!.SetValue(ctx, isJson);
            CliContextType.GetProperty("IsForce")!.SetValue(ctx, isForce);
            CliContextType.GetProperty("IsSilent")!.SetValue(ctx, isSilent);
            CliContextType.GetProperty("RemainingArgs")!.SetValue(ctx, args);
            return ctx;
        }

        private static readonly object ConsoleSyncLock = new();

        private (int ExitCode, string StdOut, string StdErr) RunSecurityCommand(object ctx, string command)
        {
            lock (ConsoleSyncLock)
            {
                var runMethod = SecurityCommandsType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
                var originalOut = Console.Out;
                var originalErr = Console.Error;
                using var swOut = new StringWriter();
                using var swErr = new StringWriter();

                try
                {
                    Console.SetOut(swOut);
                    Console.SetError(swErr);
                    int exitCode = (int)runMethod.Invoke(null, new[] { ctx, command })!;
                    return (exitCode, swOut.ToString(), swErr.ToString());
                }
                finally
                {
                    Console.SetOut(originalOut);
                    Console.SetError(originalErr);
                }
            }
        }

        // ─── 1. CliContext Tests ──────────────────────────────────────────────

        [Fact]
        public void CliContext_Properties_InitializeAndAssignCorrectly()
        {
            var ctx = CreateCliContext(isJson: true, isForce: true, isSilent: false, "sec", "defender-harden", "status");

            Assert.True((bool)CliContextType.GetProperty("IsJson")!.GetValue(ctx)!);
            Assert.True((bool)CliContextType.GetProperty("IsForce")!.GetValue(ctx)!);
            Assert.False((bool)CliContextType.GetProperty("IsSilent")!.GetValue(ctx)!);

            var remaining = (string[])CliContextType.GetProperty("RemainingArgs")!.GetValue(ctx)!;
            Assert.Equal(3, remaining.Length);
            Assert.Equal("sec", remaining[0]);
            Assert.Equal("defender-harden", remaining[1]);
            Assert.Equal("status", remaining[2]);
        }

        // ─── 2. Unknown Command Routing & Exit Code ───────────────────────────

        [Fact]
        public void SecurityCommands_UnknownCommand_ReturnsExitCode1_AndJsonEnvelope()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "invalid-subcommand-xyz");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "invalid-subcommand-xyz");

            Assert.Equal(1, exitCode);
            Assert.False(string.IsNullOrWhiteSpace(stdOut));

            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("error", out var errorProp));
            Assert.Contains("Unknown sec command", errorProp.GetString());
        }

        // ─── 3. Defender Hardener Subcommand Tests ────────────────────────────

        [Fact]
        public void SecurityCommands_DefenderHarden_Status_Json_ReturnsExitCode0_AndPureJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "status");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.Equal(0, exitCode);
            Assert.StartsWith("{", stdOut.TrimStart());

            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("AsrRules", out var asrRulesProp));
            Assert.Equal(16, asrRulesProp.GetArrayLength());
            Assert.True(root.TryGetProperty("TotalAsrRulesCount", out var totalProp));
            Assert.Equal(16, totalProp.GetInt32());
            Assert.True(root.TryGetProperty("IsPuaProtectionEnabled", out _));
            Assert.True(root.TryGetProperty("IsControlledFolderAccessEnabled", out _));
        }

        [Fact]
        public void SecurityCommands_DefenderHarden_Status_TextMode_OutputsHumanReadableTable()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "sec", "defender-harden", "status");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.Equal(0, exitCode);
            Assert.Contains("[DEFENDER] Enterprise Hardening Status", stdOut);
            Assert.Contains("PUA Protection:", stdOut);
            Assert.Contains("Attack Surface Reduction Rules:", stdOut);
        }

        [Fact]
        public void SecurityCommands_DefenderHarden_EnableAll_ReturnsValidJsonPayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "enable-all");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "defender-harden");

            // Exit code is 0 on elevated or 1 on restricted elevation
            Assert.True(exitCode == 0 || exitCode == 1);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("status", out var statusProp) || root.TryGetProperty("error", out _));
        }

        [Fact]
        public void SecurityCommands_DefenderHarden_Revert_ReturnsValidJsonPayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "defender-harden", "revert");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "defender-harden");

            Assert.True(exitCode == 0 || exitCode == 1);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("status", out _) || root.TryGetProperty("error", out _));
        }



        // ─── 4. Persistence Audit Subcommand Tests ────────────────────────────

        [Fact]
        public void SecurityCommands_PersistenceAudit_Scan_Json_ReturnsExitCode0_AndPureJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "scan");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.Equal(0, exitCode);
            Assert.StartsWith("{", stdOut.TrimStart());

            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("TotalItemsScanned", out _));
            Assert.True(root.TryGetProperty("ThreatCount", out _));
            Assert.True(root.TryGetProperty("Threats", out var threatsProp));
            Assert.Equal(JsonValueKind.Array, threatsProp.ValueKind);
        }

        [Fact]
        public void SecurityCommands_PersistenceAudit_Scan_TextMode_OutputsFormattedReport()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "sec", "persistence-audit", "scan");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.Equal(0, exitCode);
            Assert.Contains("[PERSISTENCE] Audit complete.", stdOut);
        }

        [Fact]
        public void SecurityCommands_PersistenceAudit_Remediate_ReturnsValidJsonPayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "persistence-audit", "remediate");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "persistence-audit");

            Assert.True(exitCode == 0 || exitCode == 1);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("status", out _) || root.TryGetProperty("error", out _));
        }

        // ─── 5. DNS & Hosts Check Subcommand Tests ────────────────────────────

        [Fact]
        public void SecurityCommands_HostsCheck_Status_Json_ReturnsExitCode0_AndPureJsonWithoutTrailingNoise()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, exitCode);
            string trimmed = stdOut.Trim();
            Assert.StartsWith("{", trimmed);
            Assert.EndsWith("}", trimmed);

            using var doc = JsonDocument.Parse(trimmed);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("TotalHostsEntries", out _));
            Assert.True(root.TryGetProperty("SuspiciousEntries", out var suspProp));
            Assert.Equal(JsonValueKind.Array, suspProp.ValueKind);
            Assert.True(root.TryGetProperty("NetworkAdapters", out var adapterProp));
            Assert.Equal(JsonValueKind.Array, adapterProp.ValueKind);
        }

        [Fact]
        public void SecurityCommands_HostsCheck_Status_TextMode_OutputsReport()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "sec", "hosts-check", "status");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.Equal(0, exitCode);
            Assert.Contains("[HOSTS] Hosts file contains", stdOut);
        }

        [Fact]
        public void SecurityCommands_HostsCheck_RestoreDefault_ReturnsValidPayload()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "hosts-check", "restore-default");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "hosts-check");

            Assert.True(exitCode == 0 || exitCode == 1);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("status", out _) || root.TryGetProperty("error", out _));
        }

        // ─── 6. Additional Security Handlers ──────────────────────────────────

        [Fact]
        public void SecurityCommands_FirewallSync_ReturnsExitCode0_AndJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "firewall-sync");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "firewall-sync");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.Equal("SYNCHRONIZED", root.GetProperty("status").GetString());
        }

        [Fact]
        public void SecurityCommands_AiGuard_Status_ReturnsExitCode0_AndJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "sec", "ai-guard", "status");
            var (exitCode, stdOut, _) = RunSecurityCommand(ctx, "ai-guard");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.Equal("SCAN_COMPLETE", root.GetProperty("status").GetString());
            Assert.True(root.TryGetProperty("features", out var featuresProp));
            Assert.True(featuresProp.GetArrayLength() > 0);
        }
    }
}
