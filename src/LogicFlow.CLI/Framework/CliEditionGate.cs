using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using DelgadoLogic.Core;
using Microsoft.Extensions.Logging.Abstractions;
using OmniCore.Engine;
using OmniLicense;
using OmniPulse;

namespace LogicFlow.CLI.Framework
{
    /// <summary>
    /// Enforces TierPolicy / ConsentStore / signed-license edition checks for lf.exe while preserving
    /// Zero-Hostage Revert (all unpack, restore, rollback, decompress, and boost-off operations remain unlocked on Free).
    /// </summary>
    public static class CliEditionGate
    {
        public const int ExitEditionRequired = 2;

        private static readonly string[] ValidTurboModes =
        [
            "gaming", "streaming", "rendering", "benchmarking", "minimum",
            "work", "battery", "server", "smart", "auto", "off", "status"
        ];

        /// <summary>
        /// Resolves the effective user edition fail-closed from saved Pro license token, active 14-day Pro trial,
        /// or accepted Community consent record.
        /// </summary>
        public static Edition ResolveEdition(
            string? appDataRootOverride = null,
            Func<string, string, object?>? registryReader = null)
        {
            string root = !string.IsNullOrWhiteSpace(appDataRootOverride)
                ? appDataRootOverride
                : new LogicFlowConfig().AppDataPath;

            LicenseValidation? validation = LoadSavedValidation(root);
            if (validation is { IsValid: true } && validation.Tier.ToEdition() == Edition.Pro)
                return Edition.Pro;

            try
            {
                var trial = new TrialManager(NullLogger<TrialManager>.Instance, root);
                var trialStatus = trial.PeekStatus();
                if (trialStatus is { IsActive: true, IsTampered: false })
                    return Edition.Pro;
            }
            catch
            {
                // Fail closed on unreadable trial state.
            }

            try
            {
                var consent = new ConsentStore(Path.Combine(root, "Pulse"), registryReader);
                return TierPolicy.Resolve(validation, consent.CommunityConditionAccepted());
            }
            catch
            {
                return Edition.Free;
            }
        }

        /// <summary>
        /// Loads user-configured ScanExclusions from settings.json if present.
        /// </summary>
        public static List<string> LoadScanExclusions(string? appDataRootOverride = null)
        {
            try
            {
                string root = !string.IsNullOrWhiteSpace(appDataRootOverride)
                    ? appDataRootOverride
                    : new LogicFlowConfig().AppDataPath;
                string settingsPath = Path.Combine(root, "settings.json");
                if (!File.Exists(settingsPath))
                    return new List<string>();

                using var doc = JsonDocument.Parse(File.ReadAllText(settingsPath));
                if (doc.RootElement.TryGetProperty("ScanExclusions", out var prop) &&
                    prop.ValueKind == JsonValueKind.Array)
                {
                    var result = new List<string>();
                    foreach (var el in prop.EnumerateArray())
                    {
                        if (el.ValueKind == JsonValueKind.String)
                        {
                            var val = el.GetString();
                            if (!string.IsNullOrWhiteSpace(val))
                                result.Add(val);
                        }
                    }
                    return result;
                }
            }
            catch
            {
                // Ignore malformed settings file; fail safe to empty list.
            }
            return new List<string>();
        }

        /// <summary>
        /// Checks whether the requested CLI invocation is permitted under the active edition.
        /// Returns 0 if permitted, or ExitEditionRequired (2) after writing a structured error message if blocked.
        /// </summary>
        public static int CheckAccess(CliContext ctx, string group, string command)
        {
            if (!ctx.EnforceEditionGate)
                return 0;

            Capability? required = GetRequiredCapability(group, command, ctx.RemainingArgs, ctx.IsForce);
            if (required is null || required.Value == Capability.Scan)
                return 0;

            Edition current = ctx.EditionOverride ?? ResolveEdition(ctx.AppDataRootOverride, ctx.RegistryReaderOverride);
            if (TierPolicy.IsAllowed(current, required.Value))
                return 0;

            Edition needed = TierPolicy.RequiredEdition(required.Value);
            string message = TierPolicy.UpgradeMessage(current, required.Value).Replace("\n\n", " ");
            OutputFormatter.WriteError(ctx, message, new
            {
                error = "EDITION_REQUIRED",
                currentEdition = current.ToString(),
                requiredEdition = needed.ToString(),
                capability = required.Value.ToString(),
                exitCode = ExitEditionRequired
            });
            return ExitEditionRequired;
        }

        /// <summary>
        /// Determines the required <see cref="Capability"/> for a CLI command, returning <c>null</c> only for
        /// unknown group/command names so syntax errors still report UNKNOWN_GROUP / UNKNOWN_COMMAND.
        /// </summary>
        public static Capability? GetRequiredCapability(
            string group,
            string command,
            string[] remainingArgs,
            bool isForce = false)
        {
            string g = (group ?? string.Empty).Trim().ToLowerInvariant();
            string c = (command ?? string.Empty).Trim().ToLowerInvariant();

            if (string.IsNullOrEmpty(g) || g is "help" or "--help" or "-h")
                return Capability.Scan;

            string rawGroup = g;
            string rawCommand = c;

            // Normalize top-level legacy aliases
            if (g is "boost" or "/boost" or "--boost" or "-boost"
                or "boost-off" or "/boost-off" or "--boost-off" or "-boost-off"
                or "turbo")
            {
                g = "sys";
                c = "turbo";
            }
            else if (g == "optimize")
            {
                g = "reg";
                c = "optimize";
            }
            else if (g == "rollback")
            {
                g = "reg";
                c = "rollback";
            }
            else if (g == "status")
            {
                g = "sys";
                c = "status";
            }
            else if (g == "discover")
            {
                g = "agent";
                c = "discover";
            }
            else if (g == "system")
            {
                g = "sys";
            }

            // Normalize bridged toolbox aliases
            if (g == "toolbox")
            {
                if (c == "game-compact")
                {
                    g = "app";
                    c = "game-compact";
                }
                else if (c is "vss-list" or "vss-browse" or "vss-restore")
                {
                    g = "sys";
                }
            }

            switch (g)
            {
                case "agent":
                    return c == "discover" ? Capability.Scan : null;

                case "sys":
                    return c switch
                    {
                        "status" or "telemetry-dump" or "health-check" or "trace"
                            or "smart-health" or "run-all-scans" or "boot-analyze"
                            or "vss-list" or "vss-browse" => Capability.Scan,
                        "turbo" => ResolveTurboCapability(remainingArgs, rawGroup, rawCommand),
                        "optimize-all" or "apply-safe-tweaks" or "standby-purge"
                            or "shader-clean" or "vss-restore" => Capability.Core,
                        _ => null
                    };

                case "reg":
                    return c switch
                    {
                        "rollback" => Capability.Scan, // Zero-Hostage Revert
                        "optimize" => HasAnyFlag(remainingArgs, "--scan", "--dry-run", "-s")
                            ? Capability.Scan
                            : Capability.Core,
                        "wmi-repair" or "repair-sfc" => Capability.Core,
                        _ => null
                    };

                case "sec":
                    return ResolveSecurityCapability(c, remainingArgs, isForce);

                case "app":
                    return ResolveAppCapability(c, remainingArgs, isForce);

                case "net":
                    return c switch
                    {
                        "dns-flush" or "reset-winsock" or "optimize" or "tune-tcp" => Capability.Core,
                        _ => null
                    };

                case "driver":
                    return c switch
                    {
                        "list" or "audit" or "check" or "export" or "rollback" => Capability.Scan,
                        "update" => HasAnyFlag(remainingArgs, "--scan-only", "--dry-run")
                            ? Capability.Scan
                            : Capability.Core,
                        _ => null
                    };

                case "lazarus":
                    return c switch
                    {
                        "drives" or "mtp" => Capability.Scan,
                        "carve" => Capability.AdvancedRecovery, // Pro raw sector carving
                        _ => null
                    };

                case "toolbox":
                    return c switch
                    {
                        "disk-analyze" or "duplicate-scan" => Capability.Scan,
                        "browser-clean" => HasAnyFlag(remainingArgs, "--dry-run", "--scan")
                            ? Capability.Scan
                            : Capability.Core,
                        "file-shredder" or "junk-clean" or "optimize-ram" => Capability.Core,
                        _ => null
                    };

                case "store":
                    string storeCmd = ResolveStoreSubcommand(c, remainingArgs);
                    return storeCmd switch
                    {
                        "scan" or "unpack" or "help" or "--help" or "-h" or "" => Capability.Scan, // unpack is Zero-Hostage Revert
                        "dedup" => HasAnyFlag(remainingArgs, "--dry-run")
                            ? Capability.Scan
                            : Capability.Core,
                        "pack" => Capability.Core,
                        _ => null
                    };

                default:
                    return null;
            }
        }

        public static bool IsValidTurboMode(string mode) =>
            !string.IsNullOrEmpty(mode) && Array.IndexOf(ValidTurboModes, mode) != -1;

        public static string ResolveTurboMode(
            string[] args,
            string? originalGroup = null,
            string? originalCommand = null)
        {
            string firstArg = args.Length > 0 ? args[0].Trim().ToLowerInvariant() : string.Empty;
            string grp = (originalGroup ?? string.Empty).Trim().ToLowerInvariant();
            if (grp is "boost-off" or "/boost-off" or "--boost-off" or "-boost-off" ||
                firstArg is "boost-off" or "/boost-off" or "--boost-off" or "-boost-off")
            {
                return "off";
            }

            string rawMode = "gaming";
            if (HasAnyFlag(args, "--smart", "-s"))
            {
                rawMode = "smart";
            }
            else
            {
                int modeIdx = -1;
                for (int i = 0; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "--mode", StringComparison.OrdinalIgnoreCase))
                    {
                        modeIdx = i;
                        break;
                    }
                }

                if (modeIdx != -1 && modeIdx + 1 < args.Length)
                {
                    rawMode = args[modeIdx + 1].Trim().ToLowerInvariant();
                }
                else if (args.Length > 2 && !args[2].StartsWith('-'))
                {
                    rawMode = args[2].Trim().ToLowerInvariant();
                }
                else if (args.Length > 1 && !args[1].StartsWith('-') &&
                         !string.Equals(args[1], "turbo", StringComparison.OrdinalIgnoreCase))
                {
                    rawMode = args[1].Trim().ToLowerInvariant();
                }
                else if (!string.IsNullOrWhiteSpace(originalCommand) &&
                         !originalCommand.StartsWith('-') &&
                         !string.Equals(originalCommand, "turbo", StringComparison.OrdinalIgnoreCase))
                {
                    rawMode = originalCommand.Trim().ToLowerInvariant();
                }
            }

            return rawMode switch
            {
                "on" or "enable" => "gaming",
                "disable" or "stop" => "off",
                _ => rawMode
            };
        }

        private static Capability? ResolveTurboCapability(
            string[] args,
            string? originalGroup = null,
            string? originalCommand = null)
        {
            string mode = ResolveTurboMode(args, originalGroup, originalCommand);
            if (!IsValidTurboMode(mode))
                return null; // Let SystemCommands.HandleTurbo emit INVALID_MODE

            return mode is "off" or "status" ? Capability.Scan : Capability.Core;
        }

        private static Capability? ResolveSecurityCapability(string command, string[] args, bool isForce)
        {
            string sub = args.Length > 2 ? args[2].ToLowerInvariant() : string.Empty;
            return command switch
            {
                "vuln-scan" => Capability.Scan,
                "hosts-check" => Capability.Scan, // status + restore-default (Zero-Hostage Revert)
                "ai-guard" => sub is "disable" or "disable-all" or "apply"
                    ? Capability.Core
                    : Capability.Scan, // status + revert/enable (Zero-Hostage Revert)
                "defender-harden" or "hardening-check" => sub is "enable-all" or "apply" or "harden" or "scan-offline" or "offline-scan"
                    ? Capability.Core
                    : Capability.Scan, // status, quick/full scan, and revert/default (Zero-Hostage Revert)
                "persistence-audit" => sub is "remediate" or "clean" or "fix"
                    ? Capability.Core
                    : Capability.Scan,
                "firewall-sync" => string.IsNullOrEmpty(sub) || sub is "enable" or "harden" or "sync"
                    ? Capability.Core
                    : Capability.Scan,
                "disable-exposed" => isForce ? Capability.Core : Capability.Scan,
                "privacy-shield" or "privacy-scrub" => Capability.Core,
                _ => null
            };
        }

        private static Capability? ResolveAppCapability(string command, string[] args, bool isForce)
        {
            string sub = args.Length > 2 ? args[2].ToLowerInvariant() : string.Empty;
            return command switch
            {
                "startup-audit" => Capability.Scan,
                "bloatware-purge" => (!isForce || HasAnyFlag(args, "--scan", "-s"))
                    ? Capability.Scan
                    : Capability.Core,
                "winget" => (sub == "upgrade-all" || (sub == "upgrade" && args.Length > 3))
                    ? Capability.Core
                    : Capability.Scan,
                "game-compact" => ResolveGameCompactCapability(args),
                _ => null
            };
        }

        private static Capability? ResolveGameCompactCapability(string[] args)
        {
            int gcIndex = -1;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "game-compact", StringComparison.OrdinalIgnoreCase))
                {
                    gcIndex = i;
                    break;
                }
            }

            string action = "list";
            if (gcIndex >= 0)
            {
                if (gcIndex + 1 < args.Length && !args[gcIndex + 1].StartsWith('-'))
                    action = args[gcIndex + 1].ToLowerInvariant();
            }
            else if (args.Length > 0 && !args[0].StartsWith('-'))
            {
                action = args[0].ToLowerInvariant();
            }

            return action switch
            {
                "list" or "decay-audit" or "decompress" or "help" or "--help" or "-h" => Capability.Scan, // decompress is Zero-Hostage Revert
                "compress" or "recompact" or "re-compact" => Capability.Core,
                _ => null
            };
        }

        private static string ResolveStoreSubcommand(string command, string[] args)
        {
            if (!string.IsNullOrEmpty(command))
                return command;
            if (args.Length == 1 && string.Equals(args[0], "store", StringComparison.OrdinalIgnoreCase))
                return "help";
            if (args.Length > 0 && !string.Equals(args[0], "store", StringComparison.OrdinalIgnoreCase))
                return args[0].ToLowerInvariant();
            return "help";
        }

        private static bool HasAnyFlag(string[] args, params string[] flags)
        {
            foreach (var arg in args)
            {
                foreach (var flag in flags)
                {
                    if (string.Equals(arg, flag, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        private static LicenseValidation? LoadSavedValidation(string root)
        {
            try
            {
                string licensePath = Path.Combine(root, "License", "license_token.json");
                if (!File.Exists(licensePath))
                    return null;

                string json = File.ReadAllText(licensePath);
                var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                LicenseToken? token = null;

                try
                {
                    var local = JsonSerializer.Deserialize<LocalLicenseToken>(json, opts);
                    if (local is not null && !string.IsNullOrEmpty(local.Payload))
                        token = new LicenseToken(local.Payload, local.Signature, local.Alg, local.Kid);
                }
                catch (JsonException) { /* fall through */ }

                token ??= JsonSerializer.Deserialize<LicenseToken>(json, opts);
                if (token is null)
                    return null;

                var extra = new List<string>();
                try { extra.Add(DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false).DeviceId); }
                catch { /* ignore */ }

                var validator = new RsaLicenseValidator(NullLogger<RsaLicenseValidator>.Instance);
                return validator.Validate(token, extra);
            }
            catch
            {
                return null;
            }
        }
    }
}
