<#
.SYNOPSIS  Fetch the LogicFlow telemetry daily digest (read-only).
.EXAMPLE   .\fetch-digest.ps1 -Bucket my-lf-telemetry                      # latest.md to stdout
.EXAMPLE   .\fetch-digest.ps1 -Bucket my-lf-telemetry -Date 2026-10-01 -Format json -OutFile d.json
.EXAMPLE   .\fetch-digest.ps1 -Dir .\.data                                 # local emulator data
Needs: gcloud (for -Bucket) with roles/storage.objectViewer on the bucket. Never writes to GCS.
#>
[CmdletBinding()]
param(
  [string]$Bucket = $env:LF_BUCKET,
  [string]$Dir = $env:LF_DATA_DIR,
  [ValidatePattern('^(latest|\d{4}-\d{2}-\d{2})$')][string]$Date = 'latest',
  [ValidateSet('md', 'json')][string]$Format = 'md',
  [string]$OutFile
)
$ErrorActionPreference = 'Stop'
try {
  $rel = "v1/digests/$Date.$Format"
  if ($Bucket) {
    if ($Bucket -notmatch '^[a-z0-9][a-z0-9._-]{2,221}$') { throw "Invalid bucket name '$Bucket'" }
    $gcloud = Get-Command gcloud -ErrorAction SilentlyContinue
    if (-not $gcloud) { throw 'gcloud not found on PATH' }
    $text = & gcloud storage cat "gs://$Bucket/$rel" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "gcloud storage cat failed: $text" }
    $text = ($text -join "`n")
  }
  elseif ($Dir) {
    $p = Join-Path $Dir $rel
    if (-not (Test-Path -LiteralPath $p)) { throw "Digest not found: $p" }
    $text = Get-Content -LiteralPath $p -Raw -Encoding utf8
  }
  else { throw 'Provide -Bucket (or LF_BUCKET) or -Dir (or LF_DATA_DIR).' }

  if ($OutFile) { Set-Content -LiteralPath $OutFile -Value $text -Encoding utf8; Write-Host "Wrote $OutFile" }
  else { $text }
}
catch { Write-Error $_.Exception.Message; exit 1 }
