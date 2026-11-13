<#
.SYNOPSIS
    LogicFlow Benchmark Harness
.DESCRIPTION
    Captures system performance metrics to measure optimization impact.
#>

param (
    [string]$Phase = "PreFlight", # PreFlight or PostFlight
    [string]$OutputJson = "C:\Windows\Temp\LogicFlowBenchmark.json"
)

function Get-SystemMetrics {
    $processes = Get-Process
    $os = Get-WmiObject Win32_OperatingSystem
    
    $threads = ($processes | Measure-Object -Property Threads -Sum).Sum
    $handles = ($processes | Measure-Object -Property HandleCount -Sum).Sum
    $ramUsageMB = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1024, 2)
    
    return [pscustomobject]@{
        Timestamp = (Get-Date).ToString("o")
        OSCaption = $os.Caption
        Handles   = $handles
        Threads   = $threads
        RamMB     = $ramUsageMB
    }
}

$metrics = Get-SystemMetrics
$resultObj = @{}

if (Test-Path $OutputJson) {
    try { $resultObj = Get-Content $OutputJson -Raw | ConvertFrom-Json -AsHashtable } catch { }
}

$resultObj[$Phase] = $metrics

$resultObj | ConvertTo-Json -Depth 5 | Set-Content $OutputJson

Write-Host "[$Phase] Metrics saved to $OutputJson"
Write-Host "RAM: $($metrics.RamMB) MB | Threads: $($metrics.Threads) | Handles: $($metrics.Handles)"
