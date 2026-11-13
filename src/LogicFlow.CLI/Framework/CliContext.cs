using System;
using System.IO;
using OmniLicense;

namespace LogicFlow.CLI.Framework
{
    public class CliContext
    {
        public bool IsJson { get; set; }
        public bool IsForce { get; set; }
        public bool IsSilent { get; set; }
        public string[] RemainingArgs { get; set; } = Array.Empty<string>();
        public bool EnforceEditionGate { get; set; }
        public string? AppDataRootOverride { get; set; }
        public Edition? EditionOverride { get; set; }
        public Func<string, string, object?>? RegistryReaderOverride { get; set; }
        public TextWriter? StdOutOverride { get; set; }
        public TextWriter? StdErrOverride { get; set; }
    }
}
