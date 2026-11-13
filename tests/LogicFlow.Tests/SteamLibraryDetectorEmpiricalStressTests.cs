// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — SteamLibraryDetectorEmpiricalStressTests.cs
// Empirical Challenger 1 Adversarial Stress Test Suite:
// Synthetic VDF (v1/v2), synthetic ACF & StateFlags, Epic Games manifests,
// DirectStorage heuristics across depth levels, pre-compressed extension filters,
// and Anti-Cheat / Driver exclusion safety.
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class SteamLibraryDetectorEmpiricalStressTests : IDisposable
{
    private readonly string _testScratchDir;

    public SteamLibraryDetectorEmpiricalStressTests()
    {
        _testScratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_SteamEmpirical_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testScratchDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testScratchDir))
            {
                foreach (var file in Directory.GetFiles(_testScratchDir, "*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                }
                Directory.Delete(_testScratchDir, true);
            }
        }
        catch { }
    }

    // ─── 1. Synthetic VDF Parser Stress Tests ─────────────────────────────────

    [Fact]
    public void VdfParser_HandlesV1Format_Correctly()
    {
        string vdfContent = @"
""LibraryFolders""
{
    ""TimeNextStatsReport"" ""1600000000""
    ""ContentStatsID"" ""1234567890""
    ""1"" ""D:\\SteamLibrary""
    ""2"" ""E:\\Games\\Steam""
}";

        var root = VdfParser.Parse(vdfContent);
        Assert.NotNull(root);

        var libNode = root.GetChild("LibraryFolders");
        Assert.NotNull(libNode);
        Assert.Equal("1600000000", libNode["TimeNextStatsReport"]);
        Assert.Equal("1234567890", libNode["ContentStatsID"]);
        Assert.Equal(@"D:\SteamLibrary", libNode["1"]);
        Assert.Equal(@"E:\Games\Steam", libNode["2"]);
    }

    [Fact]
    public void VdfParser_HandlesV2Format_Correctly()
    {
        string vdfContent = @"
""libraryfolders""
{
    ""0""
    {
        ""path"" ""C:\\Program Files (x86)\\Steam""
        ""label"" """"
        ""contentid"" ""11111""
        ""totalSize"" ""1000000000000""
        ""apps""
        {
            ""228980"" ""1000000""
            ""730"" ""30000000000""
        }
    }
    ""1""
    {
        ""path"" ""D:\\SteamLibrary""
        ""label"" ""FastSSD""
        ""contentid"" ""22222""
        ""totalSize"" ""2000000000000""
        ""apps""
        {
            ""1091500"" ""70000000000""
        }
    }
}";

        var root = VdfParser.Parse(vdfContent);
        Assert.NotNull(root);

        var libNode = root.GetChild("libraryfolders");
        Assert.NotNull(libNode);

        var node0 = libNode.GetChild("0");
        Assert.NotNull(node0);
        Assert.Equal(@"C:\Program Files (x86)\Steam", node0["path"]);

        var apps0 = node0.GetChild("apps");
        Assert.NotNull(apps0);
        Assert.Equal("1000000", apps0["228980"]);
        Assert.Equal("30000000000", apps0["730"]);

        var node1 = libNode.GetChild("1");
        Assert.NotNull(node1);
        Assert.Equal(@"D:\SteamLibrary", node1["path"]);
        Assert.Equal("FastSSD", node1["label"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \r\n \t  ")]
    [InlineData("// just a comment\n// second comment")]
    [InlineData("\"unclosed_block\" {\n    \"inner\" \"value\"")]
    [InlineData("\"dangling_quote\" \"val")]
    [InlineData("{\"unnamed_object\" \"val\"}")]
    public void VdfParser_MalformedAndEdgeCases_DoesNotCrash(string malformedVdf)
    {
        var root = VdfParser.Parse(malformedVdf);
        Assert.NotNull(root);
        Assert.NotNull(root.Children);
    }

    [Fact]
    public void VdfParser_DeeplyNestedBlocks_ParsesCorrectly()
    {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < 10; i++)
        {
            sb.AppendLine($"\"level_{i}\" {{");
        }
        sb.AppendLine("\"leaf_key\" \"leaf_val\"");
        for (int i = 0; i < 10; i++)
        {
            sb.AppendLine("}");
        }

        var root = VdfParser.Parse(sb.ToString());
        Assert.NotNull(root);
        var current = root.GetChild("level_0");
        for (int i = 1; i < 10; i++)
        {
            Assert.NotNull(current);
            current = current.GetChild($"level_{i}");
        }
        Assert.NotNull(current);
        Assert.Equal("leaf_val", current["leaf_key"]);
    }

    // ─── 2. Synthetic Steam Library & Manifest Detection ───────────────────────

    [Fact]
    public void DetectLibraryFolders_SyntheticV1AndV2_DiscoversAllValidLibraries()
    {
        var detector = new SteamLibraryDetector();

        // 1. Prepare synthetic Steam Root
        string steamDir = Path.Combine(_testScratchDir, "SteamMain");
        string steamAppsDir = Path.Combine(steamDir, "steamapps");
        Directory.CreateDirectory(steamAppsDir);
        File.WriteAllText(Path.Combine(steamDir, "steam.exe"), "dummy");

        // 2. Prepare secondary Library 1
        string lib1Dir = Path.Combine(_testScratchDir, "SteamLib1");
        Directory.CreateDirectory(Path.Combine(lib1Dir, "steamapps"));

        // 3. Prepare secondary Library 2
        string lib2Dir = Path.Combine(_testScratchDir, "SteamLib2");
        Directory.CreateDirectory(Path.Combine(lib2Dir, "steamapps"));

        // Test V1 libraryfolders.vdf
        string v1Content = $@"
""LibraryFolders""
{{
    ""TimeNextStatsReport"" ""1600000000""
    ""ContentStatsID"" ""1234567890""
    ""1"" ""{lib1Dir.Replace("\\", "\\\\")}""
    ""2"" ""{lib2Dir.Replace("\\", "\\\\")}""
}}";
        string vdfPath = Path.Combine(steamAppsDir, "libraryfolders.vdf");
        File.WriteAllText(vdfPath, v1Content);

        var v1Libraries = detector.DetectLibraryFolders(steamDir);
        Assert.Contains(Path.GetFullPath(steamDir), v1Libraries);
        Assert.Contains(Path.GetFullPath(lib1Dir), v1Libraries);
        Assert.Contains(Path.GetFullPath(lib2Dir), v1Libraries);

        // Test V2 libraryfolders.vdf
        string v2Content = $@"
""libraryfolders""
{{
    ""0""
    {{
        ""path"" ""{steamDir.Replace("\\", "\\\\")}""
        ""label"" """"
    }}
    ""1""
    {{
        ""path"" ""{lib1Dir.Replace("\\", "\\\\")}""
        ""label"" ""SecondarySSD""
    }}
}}";
        File.WriteAllText(vdfPath, v2Content);

        var v2Libraries = detector.DetectLibraryFolders(steamDir);
        Assert.Contains(Path.GetFullPath(steamDir), v2Libraries);
        Assert.Contains(Path.GetFullPath(lib1Dir), v2Libraries);
    }

    [Theory]
    [InlineData(4, true)]      // StateFullyInstalled = 4 -> Valid
    [InlineData(6, true)]      // StateFullyInstalled (4) | StateUpdateRunning (2) -> Valid when not downloading
    [InlineData(1028, true)]   // StateFullyInstalled (4) | StateUpdateRequired (1024) -> Valid
    [InlineData(1026, false)]  // StateUpdateRequired (1024) | StateUpdateRunning (2) -> Missing bit 4 -> Filtered
    [InlineData(1, false)]     // StateUninstalled (1) -> Filtered
    [InlineData(5, false)]     // StateFullyInstalled (4) | StateUninstalled (1) -> Filtered due to bit 1
    [InlineData(0, false)]     // None -> Filtered
    public void DetectInstalledGames_StateFlags_Matrix_CorrectlyFilters(int stateFlags, bool expectDetected)
    {
        var detector = new SteamLibraryDetector();

        string libDir = Path.Combine(_testScratchDir, $"SteamFlagsTest_{stateFlags}");
        string steamAppsDir = Path.Combine(libDir, "steamapps");
        string commonDir = Path.Combine(steamAppsDir, "common", $"TestGame_{stateFlags}");
        Directory.CreateDirectory(commonDir);

        // Add dummy file to game directory
        File.WriteAllText(Path.Combine(commonDir, "game.exe"), "executable binary payload");

        string acfContent = $@"
""AppState""
{{
    ""appid"" ""570{stateFlags}""
    ""name"" ""Test Game Flags {stateFlags}""
    ""installdir"" ""TestGame_{stateFlags}""
    ""StateFlags"" ""{stateFlags}""
    ""SizeOnDisk"" ""1048576""
    ""BytesToDownload"" ""0""
    ""BytesDownloaded"" ""0""
}}";
        File.WriteAllText(Path.Combine(steamAppsDir, $"appmanifest_570{stateFlags}.acf"), acfContent);

        var games = detector.DetectInstalledGames(new[] { libDir });

        if (expectDetected)
        {
            var game = Assert.Single(games);
            Assert.Equal($"steam_570{stateFlags}", game.GameId);
            Assert.Equal($"Test Game Flags {stateFlags}", game.Title);
            Assert.Equal(Path.GetFullPath(commonDir), game.InstallDirectory);
            Assert.Equal(1048576, game.SizeOnDiskBytes);
            Assert.Equal(LauncherType.Steam, game.Launcher);
        }
        else
        {
            Assert.Empty(games);
        }
    }

    [Fact]
    public void DetectInstalledGames_RedistributablesAndIncompleteDownloads_AreExcluded()
    {
        var detector = new SteamLibraryDetector();

        string libDir = Path.Combine(_testScratchDir, "SteamFilterTest");
        string steamAppsDir = Path.Combine(libDir, "steamapps");
        string commonDir = Path.Combine(steamAppsDir, "common");
        Directory.CreateDirectory(commonDir);

        // 1. Steamworks Common Redistributables (AppID 228980) -> Must be excluded
        string redistDir = Path.Combine(commonDir, "Steamworks Shared");
        Directory.CreateDirectory(redistDir);
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_228980.acf"), @"
""AppState""
{
    ""appid"" ""228980""
    ""name"" ""Steamworks Common Redistributables""
    ""installdir"" ""Steamworks Shared""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""500000000""
}");

        // 2. Incomplete download (BytesToDownload > BytesDownloaded) -> Must be excluded
        string incompleteDir = Path.Combine(commonDir, "IncompleteGame");
        Directory.CreateDirectory(incompleteDir);
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_12345.acf"), @"
""AppState""
{
    ""appid"" ""12345""
    ""name"" ""Incomplete Download Game""
    ""installdir"" ""IncompleteGame""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""500000000""
    ""BytesToDownload"" ""1000000000""
    ""BytesDownloaded"" ""400000000""
}");

        // 3. Complete download (BytesToDownload == BytesDownloaded) -> Must be included
        string completeDir = Path.Combine(commonDir, "CompleteGame");
        Directory.CreateDirectory(completeDir);
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_67890.acf"), @"
""AppState""
{
    ""appid"" ""67890""
    ""name"" ""Complete Game""
    ""installdir"" ""CompleteGame""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""800000000""
    ""BytesToDownload"" ""1000000000""
    ""BytesDownloaded"" ""1000000000""
}");

        // 4. Missing directory on disk -> Must be excluded
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_99999.acf"), @"
""AppState""
{
    ""appid"" ""99999""
    ""name"" ""Ghost Game""
    ""installdir"" ""GhostGameFolderDoesNotExist""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""800000000""
}");

        // 5. 0-byte ACF file -> Must not crash
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_00000.acf"), "");

        var games = detector.DetectInstalledGames(new[] { libDir });

        var detected = Assert.Single(games);
        Assert.Equal("steam_67890", detected.GameId);
        Assert.Equal("Complete Game", detected.Title);
    }

    [Fact]
    public void DetectInstalledGames_HandlesUnicodeAndSpecialCharactersInTitle()
    {
        var detector = new SteamLibraryDetector();

        string libDir = Path.Combine(_testScratchDir, "SteamUnicodeTest");
        string steamAppsDir = Path.Combine(libDir, "steamapps");
        string commonDir = Path.Combine(steamAppsDir, "common", "BlackMythWukong");
        Directory.CreateDirectory(commonDir);
        File.WriteAllText(Path.Combine(commonDir, "b1.exe"), "dummy exe");

        string acfContent = @"
""AppState""
{
    ""appid"" ""2358720""
    ""name"" ""黑神话：悟空 Black Myth: Wukong™""
    ""installdir"" ""BlackMythWukong""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""130000000000""
}";
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_2358720.acf"), acfContent, System.Text.Encoding.UTF8);

        var games = detector.DetectInstalledGames(new[] { libDir });
        var game = Assert.Single(games);

        Assert.Equal("steam_2358720", game.GameId);
        Assert.Equal("黑神话：悟空 Black Myth: Wukong", game.Title); // Trademark symbol stripped
        Assert.Equal(130000000000L, game.SizeOnDiskBytes);
    }

    // ─── 3. Synthetic Epic Manifests Stress Tests ──────────────────────────────

    [Fact]
    public void DetectEpicGames_ValidPlayableGame_DetectedWithCorrectMetadata()
    {
        var detector = new SteamLibraryDetector();

        string epicManifestsDir = Path.Combine(_testScratchDir, "EpicManifestsValid");
        Directory.CreateDirectory(epicManifestsDir);

        string gameDir = Path.Combine(_testScratchDir, "EpicGames", "Cyberpunk2077");
        Directory.CreateDirectory(Path.Combine(gameDir, "bin", "x64"));
        string exePath = Path.Combine(gameDir, "bin", "x64", "Cyberpunk2077.exe");
        File.WriteAllText(exePath, "dummy binary");

        var manifestObj = new
        {
            FormatVersion = 0,
            AppName = "Cyberpunk2077",
            DisplayName = "Cyberpunk 2077®",
            CatalogNamespace = "cyberpunk",
            InstallLocation = gameDir,
            InstallSize = 75000000000L,
            LaunchExecutable = @"bin\x64\Cyberpunk2077.exe",
            AppVersionString = "2.12",
            bIsIncompleteInstall = false,
            AppCategories = new[] { "games" }
        };

        File.WriteAllText(Path.Combine(epicManifestsDir, "CP77.item"), JsonSerializer.Serialize(manifestObj));

        var games = detector.DetectEpicGames(epicManifestsDir);
        var game = Assert.Single(games);

        Assert.Equal("epic_Cyberpunk2077", game.GameId);
        Assert.Equal("Cyberpunk 2077", game.Title); // Registered trademark symbol stripped
        Assert.Equal(Path.GetFullPath(gameDir), game.InstallDirectory);
        Assert.Equal(LauncherType.Epic, game.Launcher);
        Assert.Equal(75000000000L, game.SizeOnDiskBytes);
        Assert.Equal(Path.GetFullPath(exePath), game.PrimaryExecutablePath);
        Assert.Equal("2.12", game.AppVersion);
    }

    [Fact]
    public void DetectEpicGames_ExclusionRules_CorrectlyFiltersNonGames()
    {
        var detector = new SteamLibraryDetector();

        string epicManifestsDir = Path.Combine(_testScratchDir, "EpicManifestsExclusions");
        Directory.CreateDirectory(epicManifestsDir);

        string installBase = Path.Combine(_testScratchDir, "EpicInstalls");
        Directory.CreateDirectory(installBase);

        void CreateItem(string id, object manifestObj, bool createFolder = true)
        {
            string folder = Path.Combine(installBase, id);
            if (createFolder) Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(epicManifestsDir, $"{id}.item"), JsonSerializer.Serialize(manifestObj));
        }

        // 1. Unreal Engine Editor by catalog namespace
        CreateItem("UE_Engine", new
        {
            AppName = "UnrealEngine_5.4",
            DisplayName = "Unreal Engine 5.4",
            CatalogNamespace = "ue",
            InstallLocation = Path.Combine(installBase, "UE_Engine"),
            bIsIncompleteInstall = false
        });

        // 2. Unreal Engine Editor by AppName prefix
        CreateItem("UE_5", new
        {
            AppName = "UE_5.4",
            DisplayName = "Engine 5.4",
            CatalogNamespace = "custom",
            InstallLocation = Path.Combine(installBase, "UE_5"),
            bIsIncompleteInstall = false
        });

        // 3. Plugin / Engine extension
        CreateItem("PluginItem", new
        {
            AppName = "WaterPlugin",
            DisplayName = "Water Simulation Plugin",
            InstallLocation = Path.Combine(installBase, "PluginItem"),
            AppCategories = new[] { "plugins/engine" },
            bIsIncompleteInstall = false
        });

        // 4. Compatible apps starting with UE_
        CreateItem("UECompatible", new
        {
            AppName = "Bridge",
            DisplayName = "Quixel Bridge",
            InstallLocation = Path.Combine(installBase, "UECompatible"),
            CompatibleApps = new[] { "UE_5.3" },
            bIsIncompleteInstall = false
        });

        // 5. Prerequisites / Redistributables
        CreateItem("Prereqs", new
        {
            AppName = "PrereqTool",
            DisplayName = "DirectX Prerequisites",
            InstallLocation = Path.Combine(installBase, "Prereqs"),
            bIsIncompleteInstall = false
        });

        CreateItem("EOS", new
        {
            AppName = "EpicOnlineServices",
            DisplayName = "Epic Online Services",
            InstallLocation = Path.Combine(installBase, "EOS"),
            bIsIncompleteInstall = false
        });

        // 6. Non-launchable addons and digital extras
        CreateItem("Addon", new
        {
            AppName = "GameOST",
            DisplayName = "Game Soundtrack Addon",
            InstallLocation = Path.Combine(installBase, "Addon"),
            AppCategories = new[] { "addons" },
            bIsIncompleteInstall = false
        });

        CreateItem("DigitalExtras", new
        {
            AppName = "ArtBook",
            DisplayName = "Digital Art Book",
            InstallLocation = Path.Combine(installBase, "DigitalExtras"),
            AppCategories = new[] { "digitalextras" },
            bIsIncompleteInstall = false
        });

        // 7. Incomplete installation
        CreateItem("IncompleteGame", new
        {
            AppName = "UnfinishedGame",
            DisplayName = "Unfinished Game",
            InstallLocation = Path.Combine(installBase, "IncompleteGame"),
            bIsIncompleteInstall = true
        });

        // 8. Missing install directory
        CreateItem("MissingDirGame", new
        {
            AppName = "GhostGame",
            DisplayName = "Ghost Game",
            InstallLocation = Path.Combine(installBase, "DoesNotExist"),
            bIsIncompleteInstall = false
        }, createFolder: false);

        // 9. Malformed JSON file
        File.WriteAllText(Path.Combine(epicManifestsDir, "Corrupt.item"), "{ broken json");

        // 10. Valid Game to confirm detector is working
        CreateItem("ValidGame", new
        {
            AppName = "AlanWake2",
            DisplayName = "Alan Wake 2",
            CatalogNamespace = "aw2",
            InstallLocation = Path.Combine(installBase, "ValidGame"),
            InstallSize = 85000000000L,
            bIsIncompleteInstall = false,
            AppCategories = new[] { "games" }
        });

        var games = detector.DetectEpicGames(epicManifestsDir);
        var validGame = Assert.Single(games);
        Assert.Equal("epic_AlanWake2", validGame.GameId);
        Assert.Equal("Alan Wake 2", validGame.Title);
    }

    // ─── 4. DirectStorage Safety Heuristic Depth Tests ─────────────────────────

    [Theory]
    [InlineData(0, "dstorage.dll", true)]
    [InlineData(0, "dstoragecore.dll", true)]
    [InlineData(1, "dstorage.dll", true)]
    [InlineData(2, "dstorage.dll", true)]
    [InlineData(3, "dstorage.dll", true)]
    [InlineData(4, "dstorage.dll", false)] // Beyond default maxDepth = 3
    [InlineData(5, "dstorage.dll", false)]
    public void HasDirectStorage_TraversesDirectoryHierarchy_RespectingMaxDepth(int targetDepth, string binaryName, bool expectDetected)
    {
        string gameDir = Path.Combine(_testScratchDir, $"DS_Depth_{targetDepth}_{binaryName}");
        Directory.CreateDirectory(gameDir);

        string current = gameDir;
        for (int i = 1; i <= targetDepth; i++)
        {
            current = Path.Combine(current, $"sub_{i}");
            Directory.CreateDirectory(current);
        }

        File.WriteAllText(Path.Combine(current, binaryName), "dummy directstorage binary");

        bool hasDs = GameSafetyHeuristics.HasDirectStorage(gameDir);
        Assert.Equal(expectDetected, hasDs);

        // Also test instance extension method parity
        var detector = new SteamLibraryDetector();
        Assert.Equal(expectDetected, detector.HasDirectStorage(gameDir));
    }

    [Fact]
    public void HasDirectStorage_CustomMaxDepth_InspectsDeepDirectoriesWhenRequested()
    {
        string gameDir = Path.Combine(_testScratchDir, "DS_Deep_CustomDepth");
        string deepDir = Path.Combine(gameDir, "l1", "l2", "l3", "l4");
        Directory.CreateDirectory(deepDir);
        File.WriteAllText(Path.Combine(deepDir, "dstorage.dll"), "dummy directstorage binary");

        // Default maxDepth = 3 -> Should be false
        Assert.False(GameSafetyHeuristics.HasDirectStorage(gameDir, maxDepth: 3));

        // Explicit maxDepth = 4 -> Should be true
        Assert.True(GameSafetyHeuristics.HasDirectStorage(gameDir, maxDepth: 4));
    }

    [Theory]
    [InlineData("DSTORAGE.DLL")]
    [InlineData("DStorageCore.dll")]
    [InlineData("dstorage.DLL")]
    public void HasDirectStorage_DetectsCaseInsensitiveDirectStorageBinaries(string binaryName)
    {
        string gameDir = Path.Combine(_testScratchDir, $"DS_Case_{binaryName}");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, binaryName), "dummy DirectStorage runtime");

        Assert.True(GameSafetyHeuristics.HasDirectStorage(gameDir));
    }

    [Fact]
    public void DirectStorage_Presence_SetsEstimatedSavingsToZero()
    {
        var detector = new SteamLibraryDetector();

        string libDir = Path.Combine(_testScratchDir, "SteamDS_SavingsTest");
        string steamAppsDir = Path.Combine(libDir, "steamapps");
        string commonDir = Path.Combine(steamAppsDir, "common", "Forspoken");
        Directory.CreateDirectory(commonDir);

        // Place dstorage.dll inside Forspoken game directory
        File.WriteAllText(Path.Combine(commonDir, "dstorage.dll"), "dummy DirectStorage runtime");

        string acfContent = @"
""AppState""
{
    ""appid"" ""1680880""
    ""name"" ""Forspoken""
    ""installdir"" ""Forspoken""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""120000000000""
}";
        File.WriteAllText(Path.Combine(steamAppsDir, "appmanifest_1680880.acf"), acfContent);

        var games = detector.DetectInstalledGames(new[] { libDir });
        var game = Assert.Single(games);

        Assert.True(game.HasDirectStorage);
        Assert.Equal(0L, game.EstimatedSavingsBytes); // DirectStorage titles must report 0 estimated savings
    }

    // ─── 5. Pre-Compressed File Extension Filtering Tests ──────────────────────

    [Theory]
    [InlineData(".mp4")]
    [InlineData(".bik")]
    [InlineData(".bk2")]
    [InlineData(".webm")]
    [InlineData(".zip")]
    [InlineData(".7z")]
    [InlineData(".rar")]
    [InlineData(".ogg")]
    [InlineData(".flac")]
    [InlineData(".png")]
    [InlineData(".jpg")]
    [InlineData(".jpeg")]
    [InlineData(".pak")]
    public void IsPreCompressed_ExcludesAllSpecifiedMediaAndArchiveExtensions(string ext)
    {
        string pathLower = $@"C:\Games\Doom\assets\media{ext}";
        string pathUpper = $@"C:\Games\Doom\assets\media{ext.ToUpperInvariant()}";

        Assert.True(GameSafetyHeuristics.IsPreCompressed(pathLower), $"Expected {ext} to be pre-compressed");
        Assert.True(GameSafetyHeuristics.IsPreCompressed(pathUpper), $"Expected {ext.ToUpperInvariant()} to be pre-compressed");
        Assert.True(GameSafetyHeuristics.IsExcludedFile(pathLower), $"Expected {ext} to be excluded");
    }

    [Theory]
    [InlineData(".exe")]
    [InlineData(".dll")]
    [InlineData(".txt")]
    [InlineData(".bin")]
    [InlineData(".dat")]
    [InlineData(".json")]
    [InlineData(".ini")]
    [InlineData(".xml")]
    [InlineData(".pdb")]
    [InlineData(".cfg")]
    [InlineData(".lua")]
    [InlineData(".wad")]
    public void IsPreCompressed_AllowsCompressibleGameAssetsAndCode(string ext)
    {
        string path = $@"C:\Games\Doom\assets\file{ext}";
        Assert.False(GameSafetyHeuristics.IsPreCompressed(path), $"Expected {ext} to be compressible");
    }

    // ─── 6. Anti-Cheat & Driver Safety Exclusions Tests ─────────────────────────

    [Theory]
    [InlineData(@"C:\Windows\System32\drivers\anticheat.sys")]
    [InlineData(@"C:\Games\Valorant\Riot Vanguard\vgk.sys")]
    [InlineData(@"C:\Games\Valorant\vgtray.exe")]
    [InlineData(@"C:\Games\Elden Ring\Game\EasyAntiCheat\EasyAntiCheat_Setup.exe")]
    [InlineData(@"C:\Games\Elden Ring\Game\EasyAntiCheat\easyanticheat_eos.dll")]
    [InlineData(@"C:\Games\Apex Legends\easyanticheat_x64.dll")]
    [InlineData(@"C:\Games\Fortnite\FortniteGame\Binaries\Win64\BattlEye\BEService.exe")]
    [InlineData(@"C:\Games\Fortnite\FortniteGame\Binaries\Win64\BattlEye\BEDaisy.sys")]
    [InlineData(@"C:\Games\Fortnite\FortniteGame\Binaries\Win64\BattlEye\battleye.exe")]
    [InlineData(@"C:\Games\GenericFolder\battleye.exe")]
    [InlineData("battleye.exe")]
    [InlineData(@"C:\Games\Destiny 2\bin\x64\battleye\beclient_x64.dll")]
    [InlineData(@"C:\Games\Call of Duty\ricochet\driver.sys")]
    [InlineData(@"C:\Games\Fifa\denuvo.sys")]
    [InlineData(@"C:\Games\Fifa\dbdata.dll")]
    public void IsAntiCheatOrDriver_SafeguardsAllDriversAndAntiCheatBinaries(string filePath)
    {
        Assert.True(GameSafetyHeuristics.IsAntiCheatOrDriver(filePath), $"Expected {filePath} to be flagged as anti-cheat/driver");
        Assert.True(GameSafetyHeuristics.IsExcludedFile(filePath), $"Expected {filePath} to be excluded");
    }

    // ─── 7. EnumerateCompressibleFiles End-to-End Safety Tests ─────────────────

    [Fact]
    public void EnumerateCompressibleFiles_SkipsDirectStorageAndExcludesProtectedAssets()
    {
        string gameDir = Path.Combine(_testScratchDir, "CompressionSafetyTestGame");
        Directory.CreateDirectory(Path.Combine(gameDir, "bin"));
        Directory.CreateDirectory(Path.Combine(gameDir, "media"));
        Directory.CreateDirectory(Path.Combine(gameDir, "EasyAntiCheat"));

        // Safe Compressible Files
        string exeFile = Path.Combine(gameDir, "bin", "game.exe");
        string dllFile = Path.Combine(gameDir, "bin", "engine.dll");
        string cfgFile = Path.Combine(gameDir, "config.ini");
        File.WriteAllText(exeFile, "game binary");
        File.WriteAllText(dllFile, "engine binary");
        File.WriteAllText(cfgFile, "config payload");

        // Excluded Media & Pre-compressed Files
        File.WriteAllText(Path.Combine(gameDir, "media", "intro.mp4"), "video data");
        File.WriteAllText(Path.Combine(gameDir, "media", "cutscene.bik"), "bink video");
        File.WriteAllText(Path.Combine(gameDir, "media", "music.ogg"), "audio data");
        File.WriteAllText(Path.Combine(gameDir, "media", "splash.png"), "image data");
        File.WriteAllText(Path.Combine(gameDir, "data.pak"), "pak archive");

        // Excluded Anti-Cheat Files
        File.WriteAllText(Path.Combine(gameDir, "EasyAntiCheat", "EasyAntiCheat_Setup.exe"), "ac setup");
        File.WriteAllText(Path.Combine(gameDir, "EasyAntiCheat", "kernel.sys"), "driver");

        // 1. Without DirectStorage -> Enumerate yields ONLY compressible files
        var compressible = GameSafetyHeuristics.EnumerateCompressibleFiles(gameDir, skipDirectStorage: true).ToList();

        Assert.Contains(exeFile, compressible);
        Assert.Contains(dllFile, compressible);
        Assert.Contains(cfgFile, compressible);

        Assert.DoesNotContain(Path.Combine(gameDir, "media", "intro.mp4"), compressible);
        Assert.DoesNotContain(Path.Combine(gameDir, "media", "cutscene.bik"), compressible);
        Assert.DoesNotContain(Path.Combine(gameDir, "media", "music.ogg"), compressible);
        Assert.DoesNotContain(Path.Combine(gameDir, "media", "splash.png"), compressible);
        Assert.DoesNotContain(Path.Combine(gameDir, "data.pak"), compressible);
        Assert.DoesNotContain(Path.Combine(gameDir, "EasyAntiCheat", "EasyAntiCheat_Setup.exe"), compressible);
        Assert.DoesNotContain(Path.Combine(gameDir, "EasyAntiCheat", "kernel.sys"), compressible);

        Assert.Equal(3, compressible.Count);

        // 2. Introduce DirectStorage binary -> EnumerateCompressibleFiles must yield 0 files
        string dsPath = Path.Combine(gameDir, "bin", "dstorage.dll");
        File.WriteAllText(dsPath, "DirectStorage runtime");

        var dsSkippedFiles = GameSafetyHeuristics.EnumerateCompressibleFiles(gameDir, skipDirectStorage: true).ToList();
        Assert.Empty(dsSkippedFiles);

        // When skipDirectStorage is false -> Yields the 3 compressible files plus dstorage.dll (4 total)
        var forceEnumerateFiles = GameSafetyHeuristics.EnumerateCompressibleFiles(gameDir, skipDirectStorage: false).ToList();
        Assert.Equal(4, forceEnumerateFiles.Count);
        Assert.Contains(dsPath, forceEnumerateFiles);
    }

    // ─── 8. Custom Games Multi-Launcher Discovery Tests ────────────────────────

    [Fact]
    public void DetectCustomGames_DistinguishesSingleGameVsMultiGameDirectories()
    {
        var detector = new SteamLibraryDetector();

        // 1. Single game folder with root exe
        string singleGameDir = Path.Combine(_testScratchDir, "CustomSingleGame");
        Directory.CreateDirectory(singleGameDir);
        File.WriteAllText(Path.Combine(singleGameDir, "IndieGame.exe"), "executable");
        File.WriteAllText(Path.Combine(singleGameDir, "game.dat"), "data payload");

        var singleGames = detector.DetectCustomGames(new[] { singleGameDir });
        var single = Assert.Single(singleGames);
        Assert.Equal("CustomSingleGame", single.Title);
        Assert.Equal(LauncherType.Custom, single.Launcher);
        Assert.False(single.HasDirectStorage);

        // 2. Multi-game library folder with subdirectories
        string multiGamesParent = Path.Combine(_testScratchDir, "EmulatorsAndRoms");
        string gameA = Path.Combine(multiGamesParent, "ZeldaOcarina");
        string gameB = Path.Combine(multiGamesParent, "SuperMario64");
        Directory.CreateDirectory(gameA);
        Directory.CreateDirectory(gameB);

        File.WriteAllText(Path.Combine(gameA, "Zelda.exe"), "binary a");
        File.WriteAllText(Path.Combine(gameB, "Mario.exe"), "binary b");

        var multiGames = detector.DetectCustomGames(new[] { multiGamesParent });
        Assert.Equal(2, multiGames.Count);
        Assert.Contains(multiGames, g => g.Title == "ZeldaOcarina" && g.Launcher == LauncherType.Custom);
        Assert.Contains(multiGames, g => g.Title == "SuperMario64" && g.Launcher == LauncherType.Custom);
    }
}
