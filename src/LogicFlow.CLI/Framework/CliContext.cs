using System;

namespace LogicFlow.CLI.Framework
{
    public class CliContext
    {
        public bool IsJson { get; set; }
        public bool IsForce { get; set; }
        public bool IsSilent { get; set; }
        public string[] RemainingArgs { get; set; } = Array.Empty<string>();
    }
}
