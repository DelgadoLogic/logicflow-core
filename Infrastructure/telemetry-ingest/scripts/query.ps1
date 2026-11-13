<#
.SYNOPSIS  Run (or print) a canned BigQuery telemetry query.
.EXAMPLE   .\query.ps1 -List
.EXAMPLE   .\query.ps1 top-crashes -Project my-proj -Days 14
.EXAMPLE   .\query.ps1 version-health -Project my-proj -Print     # render SQL only, no bq call
Queries are in ..\bigquery\queries. Needs the bq CLI + bigquery.jobUser and dataViewer roles.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Name,
  [string]$Project = $env:LF_BQ_PROJECT,
  [string]$Dataset = $(if ($env:LF_BQ_DATASET) { $env:LF_BQ_DATASET } else { 'logicflow_telemetry' }),
  [ValidateRange(1, 90)][int]$Days = 7,
  [switch]$Print,
  [switch]$List
)
$ErrorActionPreference = 'Stop'
try {
  $cli = Join-Path $PSScriptRoot '..\tools\telemetry-query\lf-telemetry.js'
  if ($List) { & node $cli list; exit $LASTEXITCODE }
  if (-not $Name) { throw 'Query name required (use -List).' }
  $a = @($cli, 'query', $Name, '--days', "$Days", '--dataset', $Dataset)
  if ($Project) { $a += @('--project', $Project) }
  if ($Print) { $a += '--print' }
  & node @a
  exit $LASTEXITCODE
}
catch { Write-Error $_.Exception.Message; exit 1 }
