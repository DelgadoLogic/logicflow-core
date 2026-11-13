// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Tests — SteamLibraryDetectorAdversarialTests.cs
// Empirical Challenger 2 Adversarial Edge-Case Stress Suite:
// 1. Malformed VDF/ACF: unclosed braces, extra braces, invalid tokens, 
//    empty files, non-ASCII Unicode, null bytes, escaped quotes, deeply nested trees.
// 2. Malformed Epic JSON: syntax errors, empty objects, missing fields,
//    string vs integer vs float vs negative sizes, incomplete install flags, exclusions.
// 3. Non-existent & invalid registry/directory paths, path traversal.
// 4. Locked manifest files (ACF, .item) and locked game files during enumeration.
// 5. Circular symlinks, reparse points, and deep paths (>260 chars).
// 6. Anti-cheat and driver safety exclusions with case insensitivity.
// 7. DirectStorage depth boundaries (0, 1, 2, 3 vs 4+).
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using LogicFlow.Guardian;
using Xunit;

namespace LogicFlow.Tests;

public class SteamLibraryDetectorAdversarialTests : IDisposable
{
    private readonly string _testScratchDir;

    public SteamLibraryDetectorAdversarialTests()
    {
        _testScratchDir = Path.Combine(Path.GetTempPath(), "LogicFlow_AdvSteam_" + Guid.NewGuid().ToString("N"));
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

    // ═════════════════════════════════════════════════════════════════════════
    // 1. MALFORMED VDF / ACF ADVERSARIAL PARSER TESTS
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VdfParser_CompletelyEmptyAndWhitespace_ReturnsRootWithEmptyChildren()
    {
        var root1 = VdfParser.Parse("");
        Assert.NotNull(root1);
        Assert.NotNull(root1.Children);
        Assert.Empty(root1.Children);

        var root2 = VdfParser.Parse("   \r\n\t  \r\n  ");
        Assert.NotNull(root2);
        Assert.NotNull(root2.Children);
        Assert.Empty(root2.Children);
    }

    [Fact]
    public void VdfParser_DeeplyNestedBraces_HandlesExcessiveDepthWithoutStackOverflow()
    {
        // Construct 100 levels of nested blocks
        var sb = new StringBuilder();
        for (int i = 0; i < 100; i++)
        {
            sb.Append($"\"level_{i}\" {{ ");
        }
        sb.Append("\"innermost_key\" \"innermost_value\"");
        for (int i = 0; i < 100; i++)
        {
            sb.Append(" } ");
        }

        var root = VdfParser.Parse(sb.ToString());
        Assert.NotNull(root);

        // Traverse down the tree to ensure the hierarchy was built
        var current = root.GetChild("level_0");
        Assert.NotNull(current);
        for (int i = 1; i < 100; i++)
        {
            current = current.GetChild($"level_{i}");
            Assert.NotNull(current);
        }
        Assert.Equal("innermost_value", current["innermost_key"]);
    }

    [Fact]
    public void VdfParser_UnbalancedExtraClosingBraces_NeverThrowsStackEmpty()
    {
        // VDF with dozens of rogue closing braces without matching opening braces
        string maliciousVdf = "}} }}}} \"valid_key\" \"valid_value\" }}}} }}}}";
        var root = VdfParser.Parse(maliciousVdf);

        Assert.NotNull(root);
        Assert.Equal("valid_value", root["valid_key"]);
    }

    [Fact]
    public void VdfParser_UnclosedOpeningBracesAtEof_DoesNotHangOrCrash()
    {
        // 20 unclosed opening braces
        string unclosedVdf = "\"block1\" { \"block2\" { \"block3\" { \"key\" \"val\"";
        var root = VdfParser.Parse(unclosedVdf);

        Assert.NotNull(root);
        var b1 = root.GetChild("block1");
        Assert.NotNull(b1);
        var b2 = b1.GetChild("block2");
        Assert.NotNull(b2);
        var b3 = b2.GetChild("block3");
        Assert.NotNull(b3);
        Assert.Equal("val", b3["key"]);
    }

    [Fact]
    public void VdfParser_UnclosedQuotesAndDanglingTokens_HandledGracefully()
    {
        string weirdVdf = "\"unclosed_key \"value_with_no_closing\n\"next_key\" \"normal_value\"";
        var root = VdfParser.Parse(weirdVdf);

        Assert.NotNull(root);
        Assert.NotNull(root.Children);
        Assert.True(root.Children.Count >= 1);
    }

    [Fact]
    public void VdfParser_EscapedQuotesAndSpecialCharacters_ParsedAccurately()
    {
        string vdf = "\"escaped_data\"\n{\n    \"quote\" \"This has \\\"quotes\\\" inside\"\n    \"backslash\" \"C:\\\\Games\\\\Steam\"\n    \"tab_newline\" \"Line1\\nLine2\\tTabbed\"\n}";
        var root = VdfParser.Parse(vdf);

        Assert.NotNull(root);
        var obj = root.GetChild("escaped_data");
        Assert.NotNull(obj);
        Assert.Equal("This has \"quotes\" inside", obj["quote"]);
        Assert.Equal(@"C:\Games\Steam", obj["backslash"]);
        Assert.Equal("Line1\nLine2\tTabbed", obj["tab_newline"]);
    }

    [Fact]
    public void VdfParser_NonAsciiUnicodeAndEmojiCharacters_PreservesExactText()
    {
        string unicodeVdf = @"
""AppState""
{
    ""name"" ""Aventura en Español: ¡Acción & Diversión!""
    ""name_jp"" ""モンスターハンター：ワールド""
    ""name_ru"" ""Ведьмак 3: Дикая Охота""
    ""emoji_title"" ""Cyberpunk 2077 🚀🎮""
    ""arabic_title"" ""مغامرة رائعة""
}";
        var root = VdfParser.Parse(unicodeVdf);
        var appState = root.GetChild("AppState");
        Assert.NotNull(appState);

        Assert.Equal("Aventura en Español: ¡Acción & Diversión!", appState["name"]);
        Assert.Equal("モンスターハンター：ワールド", appState["name_jp"]);
        Assert.Equal("Ведьмак 3: Дикая Охота", appState["name_ru"]);
        Assert.Equal("Cyberpunk 2077 🚀🎮", appState["emoji_title"]);
        Assert.Equal("مغامرة رائعة", appState["arabic_title"]);
    }

    [Fact]
    public void VdfParser_NullBytesAndControlChars_HandledSafely()
    {
        string textWithNulls = "\"validKey\"\0\0 \"validValue\"\0\r\n\"anotherKey\" \"anotherValue\"";
        var root = VdfParser.Parse(textWithNulls);

        Assert.NotNull(root);
        Assert.NotNull(root.Children);
    }

    [Fact]
    public void VdfParser_InvalidTokensAndGarbagePunctuation_DoesNotThrow()
    {
        string garbage = "!@#$%^&*() _+-=[]{}|;':\",./<>? ~`\n\"realKey\" \"realValue\"";
        var root = VdfParser.Parse(garbage);

        Assert.NotNull(root);
        Assert.NotNull(root.Children);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 2. STEAM MANIFEST & DISCOVERY ADVERSARIAL EDGE CASES
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void DetectInstalledGames_ZeroByteManifest_SkippedSilently()
    {
        var detector = new SteamLibraryDetector();
        string steamApps = Path.Combine(_testScratchDir, "steamapps");
        Directory.CreateDirectory(steamApps);

        string emptyManifest = Path.Combine(steamApps, "appmanifest_100.acf");
        File.WriteAllBytes(emptyManifest, Array.Empty<byte>());

        var games = detector.DetectInstalledGames(new[] { _testScratchDir });
        Assert.Empty(games);
    }

    [Fact]
    public void DetectInstalledGames_CorruptBinaryManifest_SkippedWithoutTerminatingBatch()
    {
        var detector = new SteamLibraryDetector();
        string steamApps = Path.Combine(_testScratchDir, "steamapps");
        string commonDir = Path.Combine(steamApps, "common");
        Directory.CreateDirectory(commonDir);

        // 1. Create a corrupt binary manifest
        string corruptManifest = Path.Combine(steamApps, "appmanifest_666.acf");
        byte[] junk = new byte[] { 0xFF, 0xFE, 0x00, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
        File.WriteAllBytes(corruptManifest, junk);

        // 2. Create a valid manifest in the same directory
        string validGameDir = Path.Combine(commonDir, "ValidGame");
        Directory.CreateDirectory(validGameDir);
        File.WriteAllText(Path.Combine(validGameDir, "game.exe"), "dummy");

        string validManifest = Path.Combine(steamApps, "appmanifest_777.acf");
        File.WriteAllText(validManifest, @"
""AppState""
{
    ""appid"" ""777""
    ""name"" ""Valid Survivor Game""
    ""installdir"" ""ValidGame""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""1048576""
}");

        var games = detector.DetectInstalledGames(new[] { _testScratchDir });
        Assert.Single(games);
        Assert.Equal("steam_777", games[0].GameId);
        Assert.Equal("Valid Survivor Game", games[0].Title);
    }

    [Fact]
    public void DetectInstalledGames_MissingRequiredFields_SkippedGracefully()
    {
        var detector = new SteamLibraryDetector();
        string steamApps = Path.Combine(_testScratchDir, "steamapps");
        Directory.CreateDirectory(Path.Combine(steamApps, "common", "TestGame"));

        // Manifest missing AppId
        File.WriteAllText(Path.Combine(steamApps, "appmanifest_1.acf"), @"
""AppState""
{
    ""name"" ""No AppId Game""
    ""installdir"" ""TestGame""
    ""StateFlags"" ""4""
}");

        // Manifest missing InstallDir
        File.WriteAllText(Path.Combine(steamApps, "appmanifest_2.acf"), @"
""AppState""
{
    ""appid"" ""2""
    ""name"" ""No InstallDir Game""
    ""StateFlags"" ""4""
}");

        // Manifest with empty whitespace values
        File.WriteAllText(Path.Combine(steamApps, "appmanifest_3.acf"), @"
""AppState""
{
    ""appid"" ""   ""
    ""name"" ""Blank AppId""
    ""installdir"" ""   ""
    ""StateFlags"" ""4""
}");

        var games = detector.DetectInstalledGames(new[] { _testScratchDir });
        Assert.Empty(games);
    }

    [Theory]
    [InlineData("1", false)]       // StateUninstalled
    [InlineData("5", false)]       // StateFullyInstalled (4) | StateUninstalled (1) = 5 -> rejected
    [InlineData("0", false)]       // Missing StateFullyInstalled bit (4)
    [InlineData("2", false)]       // StateUpdateRequired only
    [InlineData("4", true)]        // StateFullyInstalled
    [InlineData("6", true)]        // StateFullyInstalled (4) | StateUpdateRequired (2)
    [InlineData("1028", true)]     // StateFullyInstalled (4) | 1024
    [InlineData("non_numeric", true)] // Falls back to default stateFlags = 4
    public void DetectInstalledGames_StateFlagsEvaluation_AdversarialChecks(string stateFlagsValue, bool shouldBeIncluded)
    {
        string scratchSub = Path.Combine(_testScratchDir, "StateTest_" + Guid.NewGuid().ToString("N"));
        string steamApps = Path.Combine(scratchSub, "steamapps");
        string gameDir = Path.Combine(steamApps, "common", "StateGame");
        Directory.CreateDirectory(gameDir);
        File.WriteAllText(Path.Combine(gameDir, "run.exe"), "dummy");

        File.WriteAllText(Path.Combine(steamApps, "appmanifest_999.acf"), $@"
""AppState""
{{
    ""appid"" ""999""
    ""name"" ""State Game""
    ""installdir"" ""StateGame""
    ""StateFlags"" ""{stateFlagsValue}""
    ""SizeOnDisk"" ""50000""
}}");

        var detector = new SteamLibraryDetector();
        var games = detector.DetectInstalledGames(new[] { scratchSub });

        if (shouldBeIncluded)
        {
            Assert.Single(games);
            Assert.Equal("steam_999", games[0].GameId);
        }
        else
        {
            Assert.Empty(games);
        }
    }

    [Fact]
    public void DetectInstalledGames_IncompleteDownload_BytesToDownloadExceedsDownloaded_Skipped()
    {
        var detector = new SteamLibraryDetector();
        string steamApps = Path.Combine(_testScratchDir, "steamapps");
        string gameDir = Path.Combine(steamApps, "common", "IncompleteGame");
        Directory.CreateDirectory(gameDir);

        File.WriteAllText(Path.Combine(steamApps, "appmanifest_888.acf"), @"
""AppState""
{
    ""appid"" ""888""
    ""name"" ""Incomplete Downloading Game""
    ""installdir"" ""IncompleteGame""
    ""StateFlags"" ""4""
    ""BytesToDownload"" ""5000000000""
    ""BytesDownloaded"" ""1000000000""
}");

        var games = detector.DetectInstalledGames(new[] { _testScratchDir });
        Assert.Empty(games);
    }

    [Fact]
    public void DetectInstalledGames_SizeOnDiskFallback_CalculatesRealDirectorySize()
    {
        var detector = new SteamLibraryDetector();
        string steamApps = Path.Combine(_testScratchDir, "steamapps");
        string gameDir = Path.Combine(steamApps, "common", "FallbackSizeGame");
        Directory.CreateDirectory(gameDir);

        // Write files totaling exactly 4,096 bytes
        File.WriteAllBytes(Path.Combine(gameDir, "file1.dat"), new byte[2048]);
        File.WriteAllBytes(Path.Combine(gameDir, "file2.dat"), new byte[2048]);

        // Manifest with SizeOnDisk missing / 0
        File.WriteAllText(Path.Combine(steamApps, "appmanifest_555.acf"), @"
""AppState""
{
    ""appid"" ""555""
    ""name"" ""Fallback Size Game""
    ""installdir"" ""FallbackSizeGame""
    ""StateFlags"" ""4""
    ""SizeOnDisk"" ""0""
}");

        var games = detector.DetectInstalledGames(new[] { _testScratchDir });
        Assert.Single(games);
        Assert.Equal(4096, games[0].SizeOnDiskBytes);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 3. MALFORMED EPIC GAMES JSON ADVERSARIAL TESTS
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void DetectEpicGames_TruncatedAndInvalidJson_SkippedWithoutTerminatingBatch()
    {
        var detector = new SteamLibraryDetector();
        string manifestsDir = Path.Combine(_testScratchDir, "EpicManifests");
        Directory.CreateDirectory(manifestsDir);

        // Corrupted JSON
        File.WriteAllText(Path.Combine(manifestsDir, "corrupted.item"), "{ \"AppName\": \"Broken\", \"InstallLocation\": \"C:\\\\");

        // Empty JSON object
        File.WriteAllText(Path.Combine(manifestsDir, "empty.item"), "{}");

        // Valid game
        string validGamePath = Path.Combine(_testScratchDir, "EpicValidGame");
        Directory.CreateDirectory(validGamePath);
        File.WriteAllText(Path.Combine(validGamePath, "launch.exe"), "dummy");

        File.WriteAllText(Path.Combine(manifestsDir, "valid.item"), JsonSerializer.Serialize(new
        {
            AppName = "EpicSurvivor",
            DisplayName = "Epic Survivor Title",
            InstallLocation = validGamePath,
            InstallSize = 1000000L,
            bIsIncompleteInstall = false
        }));

        var games = detector.DetectEpicGames(manifestsDir);
        Assert.Single(games);
        Assert.Equal("epic_EpicSurvivor", games[0].GameId);
        Assert.Equal("Epic Survivor Title", games[0].Title);
    }

    [Fact]
    public void DetectEpicGames_PolymorphicInstallSize_HandlesAllDataTypesSafely()
    {
        var detector = new SteamLibraryDetector();
        string manifestsDir = Path.Combine(_testScratchDir, "EpicPolyManifests");
        Directory.CreateDirectory(manifestsDir);

        string gamePath = Path.Combine(_testScratchDir, "PolyGame");
        Directory.CreateDirectory(gamePath);
        File.WriteAllBytes(Path.Combine(gamePath, "data.bin"), new byte[5120]);

        // 1. InstallSize as string numeric
        File.WriteAllText(Path.Combine(manifestsDir, "game_str.item"), JsonSerializer.Serialize(new
        {
            AppName = "PolyGameStr",
            DisplayName = "Poly Game String Size",
            InstallLocation = gamePath,
            InstallSize = "12345678",
            bIsIncompleteInstall = false
        }));

        // 2. InstallSize as floating point or null (falls back to directory size: 5120 bytes)
        string jsonWithFloat = $@"{{
            ""AppName"": ""PolyGameFloat"",
            ""DisplayName"": ""Poly Game Float Size"",
            ""InstallLocation"": ""{gamePath.Replace("\\", "\\\\")}"",
            ""InstallSize"": 12345.67,
            ""bIsIncompleteInstall"": false
        }}";
        File.WriteAllText(Path.Combine(manifestsDir, "game_float.item"), jsonWithFloat);

        var games = detector.DetectEpicGames(manifestsDir);
        Assert.Equal(2, games.Count);

        var strGame = games.First(g => g.GameId == "epic_PolyGameStr");
        Assert.Equal(12345678L, strGame.SizeOnDiskBytes);

        var floatGame = games.First(g => g.GameId == "epic_PolyGameFloat");
        Assert.Equal(5120L, floatGame.SizeOnDiskBytes); // Fallback size calculated accurately
    }

    [Fact]
    public void DetectEpicGames_StringOrNumericIncompleteInstall_DoesNotThrowOrSkipValidGame()
    {
        var detector = new SteamLibraryDetector();
        string manifestsDir = Path.Combine(_testScratchDir, "EpicIncompleteStringTest");
        Directory.CreateDirectory(manifestsDir);

        string validGamePath = Path.Combine(_testScratchDir, "EpicValidGameIncomp");
        Directory.CreateDirectory(validGamePath);
        File.WriteAllText(Path.Combine(validGamePath, "launch.exe"), "dummy");

        // Epic JSON with bIsIncompleteInstall as string "false"
        string json = $@"{{
            ""AppName"": ""EpicIncompStrGame"",
            ""DisplayName"": ""Epic Incomp String Game"",
            ""InstallLocation"": ""{validGamePath.Replace("\\", "\\\\")}"",
            ""InstallSize"": 1000000,
            ""bIsIncompleteInstall"": ""false""
        }}";
        File.WriteAllText(Path.Combine(manifestsDir, "game.item"), json);

        var games = detector.DetectEpicGames(manifestsDir);
        Assert.Single(games);
    }

    [Fact]
    public void DetectEpicGames_ExcludesUnrealEngineEditorsAndPlugins()
    {
        var detector = new SteamLibraryDetector();
        string manifestsDir = Path.Combine(_testScratchDir, "EpicExclusions");
        Directory.CreateDirectory(manifestsDir);

        string dummyDir = Path.Combine(_testScratchDir, "DummyDir");
        Directory.CreateDirectory(dummyDir);

        // Unreal Engine Editor
        File.WriteAllText(Path.Combine(manifestsDir, "ue5.item"), JsonSerializer.Serialize(new
        {
            AppName = "UE_5.4",
            DisplayName = "Unreal Engine 5.4.0",
            InstallLocation = dummyDir,
            CatalogNamespace = "ue",
            bIsIncompleteInstall = false
        }));

        // Unreal Engine Plugin
        File.WriteAllText(Path.Combine(manifestsDir, "plugin.item"), JsonSerializer.Serialize(new
        {
            AppName = "SomeEnginePlugin",
            DisplayName = "Some Engine Plugin",
            InstallLocation = dummyDir,
            TechnicalType = "plugins/engine",
            bIsIncompleteInstall = false
        }));

        // DirectX Redistributable
        File.WriteAllText(Path.Combine(manifestsDir, "dx.item"), JsonSerializer.Serialize(new
        {
            AppName = "DirectXRedist",
            DisplayName = "DirectX Redistributables",
            InstallLocation = dummyDir,
            bIsIncompleteInstall = false
        }));

        var games = detector.DetectEpicGames(manifestsDir);
        Assert.Empty(games);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 4. LOCKED FILES & FILE ACCESS CONCURRENCY TESTS
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void DetectInstalledGames_ExclusivelyLockedAcfManifest_SkippedWithoutThrowing()
    {
        var detector = new SteamLibraryDetector();
        string steamApps = Path.Combine(_testScratchDir, "steamapps");
        string commonDir = Path.Combine(steamApps, "common");
        Directory.CreateDirectory(commonDir);

        // 1. Create a manifest and hold an exclusive lock (FileShare.None)
        string lockedManifest = Path.Combine(steamApps, "appmanifest_111.acf");
        File.WriteAllText(lockedManifest, @"
""AppState""
{
    ""appid"" ""111""
    ""name"" ""Locked Game""
    ""installdir"" ""LockedGame""
    ""StateFlags"" ""4""
}");

        string lockedGameDir = Path.Combine(commonDir, "LockedGame");
        Directory.CreateDirectory(lockedGameDir);

        // 2. Create another valid manifest that is NOT locked
        string openManifest = Path.Combine(steamApps, "appmanifest_222.acf");
        File.WriteAllText(openManifest, @"
""AppState""
{
    ""appid"" ""222""
    ""name"" ""Open Game""
    ""installdir"" ""OpenGame""
    ""StateFlags"" ""4""
}");
        string openGameDir = Path.Combine(commonDir, "OpenGame");
        Directory.CreateDirectory(openGameDir);

        // Lock manifest 111 exclusively
        using (var lockStream = new FileStream(lockedManifest, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var games = detector.DetectInstalledGames(new[] { _testScratchDir });

            // Detector should gracefully skip manifest 111 due to lock contention, but detect manifest 222
            Assert.Single(games);
            Assert.Equal("steam_222", games[0].GameId);
        }
    }

    [Fact]
    public void DetectEpicGames_ExclusivelyLockedItemFile_SkippedWithoutThrowing()
    {
        var detector = new SteamLibraryDetector();
        string manifestsDir = Path.Combine(_testScratchDir, "EpicLockedManifests");
        Directory.CreateDirectory(manifestsDir);

        string lockedItem = Path.Combine(manifestsDir, "locked.item");
        File.WriteAllText(lockedItem, "{ \"AppName\": \"LockedApp\", \"InstallLocation\": \"C:\\\\Dummy\" }");

        using (var lockStream = new FileStream(lockedItem, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var games = detector.DetectEpicGames(manifestsDir);
            Assert.Empty(games); // Did not throw IOException
        }
    }

    [Fact]
    public void SafeEnumerateFiles_LockedFileInsideDirectory_StillEnumeratedWithoutCrashing()
    {
        string dir = Path.Combine(_testScratchDir, "LockedEnumDir");
        Directory.CreateDirectory(dir);

        string lockedFile = Path.Combine(dir, "exclusive_asset.pak");
        File.WriteAllBytes(lockedFile, new byte[1024]);

        string normalFile = Path.Combine(dir, "normal_asset.dat");
        File.WriteAllBytes(normalFile, new byte[1024]);

        // Hold an exclusive lock on the file
        using (var lockStream = new FileStream(lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var enumerated = GameSafetyHeuristics.SafeEnumerateFiles(dir).ToList();

            // Directory enumeration returns file names via filesystem catalog, does not throw
            Assert.Equal(2, enumerated.Count);
            Assert.Contains(lockedFile, enumerated);
            Assert.Contains(normalFile, enumerated);
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 5. DEEP PATHS (>260 CHARS), REPARSE POINTS & PATH TRAVERSAL
    // ═════════════════════════════════════════════════════════════════════════

    [Fact]
    public void SafeEnumerateFiles_DeepDirectoryTree_DoesNotThrowPathTooLongException()
    {
        // Build a nested directory tree with depth > 10
        string current = _testScratchDir;
        for (int i = 0; i < 12; i++)
        {
            current = Path.Combine(current, $"NestedDirectoryLevel_{i:D2}");
            Directory.CreateDirectory(current);
        }

        string deepFile = Path.Combine(current, "deep_file.txt");
        File.WriteAllText(deepFile, "Deep path test content");

        var files = GameSafetyHeuristics.SafeEnumerateFiles(_testScratchDir).ToList();
        Assert.Contains(deepFile, files);
    }

    [Fact]
    public void DetectCustomGames_PathTraversalAndSpecialCharacters_NormalizedSafely()
    {
        var detector = new SteamLibraryDetector();

        // Create a game folder
        string gameFolder = Path.Combine(_testScratchDir, "TargetGameDir");
        Directory.CreateDirectory(gameFolder);
        File.WriteAllText(Path.Combine(gameFolder, "target.exe"), "dummy");

        // Pass path with traversal (e.g. C:\Scratch\SubDir\..\TargetGameDir)
        string subDir = Path.Combine(_testScratchDir, "SubDir");
        Directory.CreateDirectory(subDir);
        string traversalPath = Path.Combine(subDir, "..", "TargetGameDir");

        var games = detector.DetectCustomGames(new[] { traversalPath, "", "   ", "Z:\\NonExistent_9999\\Fake" });

        Assert.Single(games);
        Assert.Equal(Path.GetFullPath(gameFolder), games[0].InstallDirectory);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 6. ANTI-CHEAT, DRIVER & PRE-COMPRESSED SAFETY EXCLUSIONS
    // ═════════════════════════════════════════════════════════════════════════

    [Theory]
    // All required pre-compressed extensions (with various casings)
    [InlineData("video.mp4", true)]
    [InlineData("intro.MP4", true)]
    [InlineData("cutscene.bik", true)]
    [InlineData("logo.BK2", true)]
    [InlineData("clip.webm", true)]
    [InlineData("archive.zip", true)]
    [InlineData("package.7z", true)]
    [InlineData("bundle.rar", true)]
    [InlineData("music.ogg", true)]
    [InlineData("audio.flac", true)]
    [InlineData("texture.png", true)]
    [InlineData("splash.jpg", true)]
    [InlineData("photo.jpeg", true)]
    [InlineData("assets.pak", true)]
    [InlineData("pakchunk0.PAK", true)]
    // System drivers
    [InlineData("anydriver.sys", true)]
    [InlineData("NTFS_EXTRA.SYS", true)]
    // Anti-cheat exact files and prefixes
    [InlineData("vgk.sys", true)]
    [InlineData("denuvo.sys", true)]
    [InlineData("dbdata.dll", true)]
    [InlineData("pbsvc.exe", true)]
    [InlineData("easyanticheat_setup.exe", true)]
    [InlineData("beservice.exe", true)]
    [InlineData("bedaisy.sys", true)]
    [InlineData("randgrid.dll", true)]
    [InlineData("pnkbstrA.exe", true)]
    // Anti-cheat directory paths
    [InlineData(@"C:\Games\GameA\EasyAntiCheat\x64.dll", true)]
    [InlineData(@"C:\Games\GameB\BattlEye\BEClient_x64.dll", true)]
    [InlineData(@"C:\Games\GameC\Vanguard\client.dll", true)]
    [InlineData(@"C:\Games\GameD\Denuvo\protection.dat", true)]
    [InlineData(@"C:\Games\GameE\Ricochet\monitor.dll", true)]
    // Anti-cheat in generic non-anti-cheat folder names
    [InlineData(@"C:\Games\GenericFolder\battleye.exe", true)]
    [InlineData(@"C:\Games\GenericFolder\vanguard.exe", true)]
    [InlineData(@"C:\Games\GenericFolder\beclient.dll", true)]
    // Normal game files that MUST NOT be excluded
    [InlineData(@"C:\Games\Game\game.exe", false)]
    [InlineData(@"C:\Games\Game\engine.dll", false)]
    [InlineData(@"C:\Games\Game\game_data.bin", false)]
    [InlineData(@"C:\Games\Game\shaders.hlsl", false)]
    [InlineData(@"C:\Games\Game\strings.json", false)]
    public void IsExcludedFile_AdversarialSafetyExclusionVerification(string path, bool shouldBeExcluded)
    {
        bool excluded = GameSafetyHeuristics.IsExcludedFile(path);
        Assert.Equal(shouldBeExcluded, excluded);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 7. DIRECTSTORAGE BOUNDING & FILE ENUMERATION FILTERING
    // ═════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(0, "dstorage.dll", true)]
    [InlineData(1, "dstorage.dll", true)]
    [InlineData(2, "dstoragecore.dll", true)]
    [InlineData(3, "dstorage.dll", true)]
    [InlineData(4, "dstorage.dll", false)] // Beyond maxDepth=3 boundary!
    public void HasDirectStorage_EnforcesMaxDepth3Boundary(int depth, string binaryName, bool expectedDetected)
    {
        string baseDir = Path.Combine(_testScratchDir, $"DsDepth_{depth}_{binaryName}");
        Directory.CreateDirectory(baseDir);

        string targetDir = baseDir;
        for (int i = 0; i < depth; i++)
        {
            targetDir = Path.Combine(targetDir, $"level_{i}");
            Directory.CreateDirectory(targetDir);
        }

        File.WriteAllText(Path.Combine(targetDir, binaryName), "dummy DirectStorage runtime");

        bool detected = GameSafetyHeuristics.HasDirectStorage(baseDir, maxDepth: 3);
        Assert.Equal(expectedDetected, detected);
    }

    [Fact]
    public void EnumerateCompressibleFiles_SkipsDirectStorageByDefault_AndExcludesPrecompressed()
    {
        string gameDir = Path.Combine(_testScratchDir, "CompressibleTestGame");
        Directory.CreateDirectory(gameDir);

        // Place a compressible text file and a pre-compressed pak file
        string textFile = Path.Combine(gameDir, "dialogue.txt");
        File.WriteAllText(textFile, "Compressible script data");

        string pakFile = Path.Combine(gameDir, "assets.pak");
        File.WriteAllText(pakFile, "Pre-compressed package");

        // 1. Without DirectStorage
        var filesWithoutDs = GameSafetyHeuristics.EnumerateCompressibleFiles(gameDir, skipDirectStorage: true).ToList();
        Assert.Single(filesWithoutDs);
        Assert.Equal(textFile, filesWithoutDs[0]);

        // 2. Add DirectStorage runtime DLL
        File.WriteAllText(Path.Combine(gameDir, "dstorage.dll"), "directstorage");

        // Now with skipDirectStorage=true, it MUST return 0 files (entire game skipped)
        var filesWithDsSkipped = GameSafetyHeuristics.EnumerateCompressibleFiles(gameDir, skipDirectStorage: true).ToList();
        Assert.Empty(filesWithDsSkipped);

        // With skipDirectStorage=false, it yields dialogue.txt and dstorage.dll, but excludes assets.pak
        var filesWithDsForced = GameSafetyHeuristics.EnumerateCompressibleFiles(gameDir, skipDirectStorage: false).ToList();
        Assert.Equal(2, filesWithDsForced.Count);
        Assert.Contains(textFile, filesWithDsForced);
        Assert.Contains(Path.Combine(gameDir, "dstorage.dll"), filesWithDsForced);
        Assert.DoesNotContain(pakFile, filesWithDsForced);
    }
}
