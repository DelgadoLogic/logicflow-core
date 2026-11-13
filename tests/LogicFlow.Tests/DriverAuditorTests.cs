// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests – DriverAuditorTests
// Comprehensive unit tests for DriverAuditorEngine and CLI DriverCommands.
// Tests real and simulated device auditing, outdated & unsigned detection,
// ConfigManagerErrorCode mapping, JSON/CSV exports, and CLI execution.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests
{
    [Collection("CliConsoleExecution")]
    public class DriverAuditorTests : IDisposable
    {
        private static readonly Assembly CliAssembly = LoadCliAssembly();
        private static readonly Type CliContextType = CliAssembly.GetType("LogicFlow.CLI.Framework.CliContext")!;
        private static readonly Type DriverCommandsType = CliAssembly.GetType("LogicFlow.CLI.Commands.DriverCommands")!;

        private readonly List<string> _tempFiles = new();

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

        private (int ExitCode, string StdOut, string StdErr) RunDriverCommand(object ctx, string command)
        {
            lock (ConsoleSyncLock)
            {
                var runMethod = DriverCommandsType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;
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

        public void Dispose()
        {
            foreach (var file in _tempFiles)
            {
                try
                {
                    if (File.Exists(file)) File.Delete(file);
                }
                catch { }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  1. AuditDrivers() with Real and Simulated Devices
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void AuditDrivers_RealHost_ReturnsValidReport()
        {
            var engine = new DriverAuditorEngine();
            var report = engine.AuditDrivers();

            Assert.NotNull(report);
            Assert.NotNull(report.Drivers);
            Assert.True(report.TotalDrivers >= 0);
            Assert.True(report.UpToDateCount >= 0);
            Assert.True(report.OutdatedCount >= 0);
            Assert.True(report.UnsignedCount >= 0);
            Assert.True(report.ProblemDeviceCount >= 0);

            foreach (var driver in report.Drivers)
            {
                Assert.False(string.IsNullOrWhiteSpace(driver.DeviceName));
                Assert.NotNull(driver.StatusDescription);
            }
        }

        [Fact]
        public void QuerySetupApiDrivers_ExecutesFallbackDirectly_ReturnsList()
        {
            var engine = new DriverAuditorEngine();
            var drivers = engine.QuerySetupApiDrivers();

            Assert.NotNull(drivers);
            // SetupAPI should succeed on any standard Windows machine
            Assert.NotEmpty(drivers);
            Assert.All(drivers, d => Assert.False(string.IsNullOrWhiteSpace(d.DeviceName)));
        }

        [Fact]
        public void AuditDrivers_SimulatedDeviceCollection_CalculatesMetricsCorrectly()
        {
            var drivers = new List<DriverAuditorEngine.DeviceDriverInfo>
            {
                new()
                {
                    DeviceName = "Intel Wi-Fi 6 AX200",
                    Manufacturer = "Intel",
                    DriverVersion = "22.190.0.4",
                    DriverDate = DateTime.Now.AddMonths(-3).ToString("yyyy-MM-dd"),
                    IsSigned = true,
                    Signer = "Microsoft Windows Hardware Compatibility",
                    ConfigManagerErrorCode = 0
                },
                new()
                {
                    DeviceName = "Legacy Generic USB Serial",
                    Manufacturer = "Prolific",
                    DriverVersion = "1.5.0.0",
                    DriverDate = DateTime.Now.AddYears(-5).ToString("yyyy-MM-dd"),
                    IsSigned = true,
                    Signer = "Prolific Technology",
                    ConfigManagerErrorCode = 0
                },
                new()
                {
                    DeviceName = "Virtual Audio Cable Demo",
                    Manufacturer = "Custom",
                    DriverVersion = "0.9.1.0",
                    DriverDate = DateTime.Now.AddMonths(-1).ToString("yyyy-MM-dd"),
                    IsSigned = false,
                    Signer = "",
                    ConfigManagerErrorCode = 0
                },
                new()
                {
                    DeviceName = "Faulty PCI Express Root Port",
                    Manufacturer = "Standard System Devices",
                    DriverVersion = "10.0.22621.1",
                    DriverDate = DateTime.Now.AddYears(-1).ToString("yyyy-MM-dd"),
                    IsSigned = true,
                    Signer = "Microsoft Windows",
                    ConfigManagerErrorCode = 10
                }
            };

            var report = new DriverAuditorEngine.DriverAuditReport
            {
                Drivers = drivers
            };

            Assert.Equal(4, report.TotalDrivers);
            Assert.Equal(1, report.UpToDateCount);
            Assert.Equal(1, report.OutdatedCount);
            Assert.Equal(1, report.UnsignedCount);
            Assert.Equal(1, report.ProblemDeviceCount);

            var engine = new DriverAuditorEngine();
            var summary = engine.CheckDriverStatus(report);

            Assert.Equal(4, summary.Total);
            Assert.Equal(1, summary.UpToDate);
            Assert.Equal(1, summary.Outdated);
            Assert.Equal(1, summary.Unsigned);
            Assert.Equal(1, summary.ErrorCount);
        }

        // ═══════════════════════════════════════════════════════════════════
        //  2. Outdated and Unsigned Driver Detection
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void DeviceDriverInfo_OutdatedDriver_DetectedCorrectly()
        {
            var oldDriver = new DriverAuditorEngine.DeviceDriverInfo
            {
                DeviceName = "Old Display Adapter",
                DriverDate = "2019-05-12",
                IsSigned = true,
                ConfigManagerErrorCode = 0
            };

            Assert.True(oldDriver.IsOutdated);
            Assert.Equal("Outdated Driver", oldDriver.StatusDescription);
        }

        [Fact]
        public void DeviceDriverInfo_RecentDriver_NotOutdated()
        {
            var recentDriver = new DriverAuditorEngine.DeviceDriverInfo
            {
                DeviceName = "Modern GPU Driver",
                DriverDate = DateTime.Now.AddMonths(-2).ToString("yyyy-MM-dd"),
                IsSigned = true,
                ConfigManagerErrorCode = 0
            };

            Assert.False(recentDriver.IsOutdated);
            Assert.Equal("OK", recentDriver.StatusDescription);
        }

        [Fact]
        public void DeviceDriverInfo_UnsignedDriver_DetectedCorrectly()
        {
            var unsignedDriver = new DriverAuditorEngine.DeviceDriverInfo
            {
                DeviceName = "Experimental Test Driver",
                DriverDate = DateTime.Now.AddMonths(-1).ToString("yyyy-MM-dd"),
                IsSigned = false,
                ConfigManagerErrorCode = 0
            };

            Assert.False(unsignedDriver.IsSigned);
            Assert.Equal("Unsigned Driver", unsignedDriver.StatusDescription);
        }

        [Theory]
        [InlineData("20180101000000.000000-000", true)]
        [InlineData("2019-01-01", true)]
        [InlineData("01/01/2019", true)]
        [InlineData("2030-01-01", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        [InlineData("not-a-date", false)]
        public void IsDateOutdated_VariousDateFormats_EvaluatesProperly(string? dateStr, bool expectedOutdated)
        {
            var referenceDate = new DateTime(2026, 9, 1);
            bool actual = DriverAuditorEngine.IsDateOutdated(dateStr!, referenceDate);
            Assert.Equal(expectedOutdated, actual);
        }

        [Fact]
        public void FormatDriverDate_WmiCimFormat_ReturnsIsoDate()
        {
            string wmiDate = "20210825000000.000000-000";
            string formatted = DriverAuditorEngine.FormatDriverDate(wmiDate);
            Assert.Equal("2021-08-25", formatted);
        }

        // ═══════════════════════════════════════════════════════════════════
        //  3. Problem Device Error Description Mapping
        // ═══════════════════════════════════════════════════════════════════

        [Theory]
        [InlineData(0, "working properly")]
        [InlineData(1, "not configured correctly")]
        [InlineData(3, "corrupted")]
        [InlineData(10, "cannot start")]
        [InlineData(12, "resources")]
        [InlineData(14, "restart")]
        [InlineData(18, "Reinstall")]
        [InlineData(22, "disabled")]
        [InlineData(28, "not installed")]
        [InlineData(31, "not working properly")]
        [InlineData(43, "reported problems")]
        [InlineData(52, "digital signature")]
        public void GetErrorCodeDescription_StandardCodes_ReturnClearDescriptions(int code, string keyword)
        {
            string desc = DriverAuditorEngine.GetErrorCodeDescription(code);
            Assert.False(string.IsNullOrWhiteSpace(desc));
            Assert.Contains(keyword, desc, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GetErrorCodeDescription_UnknownCode_ReturnsFormattedError()
        {
            string desc = DriverAuditorEngine.GetErrorCodeDescription(8888);
            Assert.Equal("Device Error (Code 8888)", desc);
        }

        [Fact]
        public void DeviceDriverInfo_WithError_PrioritizesErrorDescription()
        {
            var device = new DriverAuditorEngine.DeviceDriverInfo
            {
                DeviceName = "Problem Sensor",
                ConfigManagerErrorCode = 10,
                IsSigned = false,
                DriverDate = "2018-01-01"
            };

            Assert.True(device.HasError);
            Assert.Contains("cannot start", device.StatusDescription, StringComparison.OrdinalIgnoreCase);
        }

        // ═══════════════════════════════════════════════════════════════════
        //  4. ExportDriverReport() — JSON and CSV
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void ExportDriverReport_JsonFormat_ExportsValidJson()
        {
            var engine = new DriverAuditorEngine();
            string tempFile = Path.Combine(Path.GetTempPath(), $"driver_test_{Guid.NewGuid():N}.json");
            _tempFiles.Add(tempFile);

            var simulatedReport = new DriverAuditorEngine.DriverAuditReport
            {
                Drivers = new List<DriverAuditorEngine.DeviceDriverInfo>
                {
                    new()
                    {
                        DeviceName = "Test Graphics Controller",
                        Manufacturer = "NVIDIA",
                        DriverVersion = "550.40",
                        DriverDate = "2024-02-01",
                        HardwareId = @"PCI\VEN_10DE&DEV_1F08",
                        IsSigned = true,
                        Signer = "Microsoft Windows Hardware Compatibility",
                        ConfigManagerErrorCode = 0
                    }
                }
            };

            string exported = engine.ExportDriverReport(tempFile, "json", simulatedReport);

            Assert.True(File.Exists(exported));
            string jsonContent = File.ReadAllText(exported);
            using var doc = JsonDocument.Parse(jsonContent);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("TotalDrivers", out var totalProp));
            Assert.Equal(1, totalProp.GetInt32());
            Assert.True(root.TryGetProperty("Drivers", out var driversArray));
            Assert.Equal(1, driversArray.GetArrayLength());
        }

        [Fact]
        public void ExportDriverReport_CsvFormat_ExportsValidCsv()
        {
            var engine = new DriverAuditorEngine();
            string tempFile = Path.Combine(Path.GetTempPath(), $"driver_test_{Guid.NewGuid():N}.csv");
            _tempFiles.Add(tempFile);

            var simulatedReport = new DriverAuditorEngine.DriverAuditReport
            {
                Drivers = new List<DriverAuditorEngine.DeviceDriverInfo>
                {
                    new()
                    {
                        DeviceName = "Realtek High Definition Audio",
                        Manufacturer = "Realtek",
                        DriverVersion = "6.0.9200.1",
                        DriverDate = "2021-06-15",
                        HardwareId = @"HDAUDIO\FUNC_01&VEN_10EC",
                        IsSigned = true,
                        Signer = "Microsoft Windows",
                        ConfigManagerErrorCode = 0
                    }
                }
            };

            string exported = engine.ExportDriverReport(tempFile, "csv", simulatedReport);

            Assert.True(File.Exists(exported));
            var lines = File.ReadAllLines(exported);
            Assert.True(lines.Length >= 2);
            Assert.StartsWith("DeviceName,Manufacturer,DriverVersion", lines[0]);
            Assert.Contains("Realtek High Definition Audio", lines[1]);
        }

        [Fact]
        public void ExportDriverReport_EmptyPath_ThrowsArgumentException()
        {
            var engine = new DriverAuditorEngine();
            Assert.Throws<ArgumentException>(() => engine.ExportDriverReport(""));
        }

        // ═══════════════════════════════════════════════════════════════════
        //  5. CLI DriverCommands.Run for list, audit, export, rollback
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void DriverCommands_List_HumanReadable_ReturnsZero()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "driver", "list");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "list");

            Assert.Equal(0, exitCode);
            Assert.Contains("[DRIVER]", stdOut);
            Assert.Contains("DEVICE NAME", stdOut);
        }

        [Fact]
        public void DriverCommands_List_Json_ReturnsZeroAndValidJson()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "list");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "list");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("total", out var totalProp));
            Assert.True(totalProp.GetInt32() >= 0);
            Assert.True(root.TryGetProperty("drivers", out var driversArray));
            Assert.Equal(JsonValueKind.Array, driversArray.ValueKind);
        }

        [Fact]
        public void DriverCommands_Audit_HumanReadable_ReturnsZero()
        {
            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "driver", "audit");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "audit");

            Assert.Equal(0, exitCode);
            Assert.Contains("[DRIVER]", stdOut);
            Assert.Contains("Audited", stdOut);
        }

        [Fact]
        public void DriverCommands_Audit_Json_ReturnsZeroAndSummary()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "audit");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "audit");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("total", out var totalProp));
            Assert.True(totalProp.GetInt32() >= 0);
            Assert.True(root.TryGetProperty("upToDate", out _));
            Assert.True(root.TryGetProperty("outdated", out _));
            Assert.True(root.TryGetProperty("unsigned", out _));
            Assert.True(root.TryGetProperty("errorCount", out _));
        }

        [Fact]
        public void DriverCommands_Check_Alias_ExecutesAuditSuccessfully()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "check");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "check");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("total", out _));
        }

        [Fact]
        public void DriverCommands_Export_Json_CreatesFileAndReturnsZero()
        {
            string exportPath = Path.Combine(Path.GetTempPath(), $"cli_export_{Guid.NewGuid():N}.json");
            _tempFiles.Add(exportPath);

            var ctx = CreateCliContext(isJson: false, isForce: false, isSilent: false, "driver", "export", exportPath);
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "export");

            Assert.Equal(0, exitCode);
            Assert.Contains("successfully exported", stdOut);
            Assert.True(File.Exists(exportPath));
        }

        [Fact]
        public void DriverCommands_Export_Csv_CreatesFileAndReturnsZero()
        {
            string exportPath = Path.Combine(Path.GetTempPath(), $"cli_export_{Guid.NewGuid():N}.csv");
            _tempFiles.Add(exportPath);

            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "export", exportPath);
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "export");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("status", out var statusProp));
            Assert.Equal("EXPORT_SUCCESS", statusProp.GetString());
            Assert.True(File.Exists(exportPath));
        }

        [Fact]
        public void DriverCommands_Export_MissingPath_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "export");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "export");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("error", out var errorProp));
            Assert.Contains("Usage", errorProp.GetString());
        }

        [Fact]
        public void DriverCommands_Rollback_WithTarget_ReturnsZeroAndInstructions()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "rollback", "ROOT_DEVICE_01");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "rollback");

            Assert.Equal(0, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("status", out var statusProp));
            Assert.Equal("ROLLBACK_VALIDATED", statusProp.GetString());
            Assert.True(root.TryGetProperty("rollbackInstructions", out var instrArray));
            Assert.True(instrArray.GetArrayLength() > 0);
        }

        [Fact]
        public void DriverCommands_Rollback_MissingDeviceId_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "rollback");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "rollback");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("error", out var errorProp));
            Assert.Contains("Usage", errorProp.GetString());
        }

        [Fact]
        public void DriverCommands_UnknownCommand_ReturnsExitCode1()
        {
            var ctx = CreateCliContext(isJson: true, isForce: false, isSilent: false, "driver", "nonexistent-cmd");
            var (exitCode, stdOut, _) = RunDriverCommand(ctx, "nonexistent-cmd");

            Assert.Equal(1, exitCode);
            using var doc = JsonDocument.Parse(stdOut);
            Assert.True(doc.RootElement.TryGetProperty("error", out var errorProp));
            Assert.Contains("Unknown driver command", errorProp.GetString());
        }

        // ═══════════════════════════════════════════════════════════════════
        //  6. False-Positive Audio Endpoints & Bluetooth Profiles Filtering
        // ═══════════════════════════════════════════════════════════════════

        [Theory]
        [InlineData("1 - RS4C18a.U AMD High Definition Audio Device", "AMD", "Media", @"MMDEVAPI\AudioEndpoints", false)]
        [InlineData("AirPods Max", "Apple", "Bluetooth", @"BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}_LOCALMFG&004c", false)]
        [InlineData("AirPods Max Avrcp Transport", "Microsoft", "Bluetooth", @"BTHENUM\{0000110e-0000-1000-8000-00805f9b34fb}", false)]
        [InlineData("AirPods Max Hands-Free", "Microsoft", "Bluetooth", @"BTHHFENUM\BthHfPhone", false)]
        [InlineData("OBS Virtual Camera", "OBS Project", "Camera", @"SWD\OBS_VIRTUAL_CAM", false)]
        [InlineData("Realtek High Definition Audio", "Realtek", "Media", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0892", true)]
        [InlineData("AMD High Definition Audio Controller", "Advanced Micro Devices", "Media", @"PCI\VEN_1002&DEV_AA01", true)]
        [InlineData("Intel(R) Wireless Bluetooth(R)", "Intel Corporation", "Bluetooth", @"USB\VID_8087&PID_0029", true)]
        public void IsPhysicalOemHardware_FiltersFalsePositivesAccurately(string name, string mfr, string cls, string hwid, bool expectedPhysical)
        {
            bool actual = DriverAuditorEngine.IsPhysicalOemHardware(name, mfr, cls, hwid, hwid, 0);
            Assert.Equal(expectedPhysical, actual);
        }

        [Fact]
        public void IsVirtualOrInboxDevice_IdentifiesEndpointsAndAccessories()
        {
            Assert.True(DriverAuditorEngine.IsVirtualOrInboxDevice(
                "1 - RS4C18a.U AMD High Definition Audio Device", "AMD", "Media", @"MMDEVAPI\AudioEndpoints"));

            Assert.True(DriverAuditorEngine.IsVirtualOrInboxDevice(
                "AirPods Max", "Apple", "Bluetooth", @"BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}"));

            Assert.True(DriverAuditorEngine.IsVirtualOrInboxDevice(
                "OBS Virtual Camera", "OBS", "Camera", @"SWD\VIRTUAL_CAM"));
        }

        // ═══════════════════════════════════════════════════════════════════
        //  7. Specialized Audio Codec Fallback Protection
        // ═══════════════════════════════════════════════════════════════════

        [Theory]
        [InlineData("Senary Audio", "Senary", "Audio", @"HDAUDIO\FUNC_01&VEN_14F1&DEV_5111", "", "")]
        [InlineData("Conexant SmartAudio HD", "Conexant", "Audio", @"HDAUDIO\FUNC_01&VEN_14F1&DEV_506E", "", "")]
        [InlineData("Synaptics HD Audio", "Synaptics", "Audio", @"HDAUDIO\FUNC_01&VEN_14F1", "", "")]
        [InlineData("C-Media USB Audio Device", "C-Media", "Audio", @"USB\VID_0D8C&PID_0014", "", "")]
        [InlineData("Realtek High Definition Audio", "Realtek", "Audio", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0892", "6.0.9655.1", "2024-03-20")]
        [InlineData("Intel(R) Smart Sound Technology (Intel(R) SST) Audio Controller", "Intel", "Audio", @"PCI\VEN_8086&DEV_02C8", "10.29.0.10300", "2024-04-05")]
        [InlineData("Intel(R) Display Audio", "Intel(R) Corporation", "Audio", @"HDAUDIO\FUNC_01&VEN_8086&DEV_280B", "", "")]
        public void GetTargetVersion_ProtectsSpecializedAudioCodecsFromIntelSstFallback(
            string name, string mfr, string category, string hwid, string expectedVer, string expectedDate)
        {
            var (version, date) = DriverAuditorEngine.GetTargetVersion(name, mfr, category, hwid);
            Assert.Equal(expectedVer, version);
            Assert.Equal(expectedDate, date);
        }
    }
}
