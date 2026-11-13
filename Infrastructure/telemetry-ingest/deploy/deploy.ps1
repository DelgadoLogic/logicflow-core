<#
.SYNOPSIS
  Provision + deploy the LogicFlow telemetry ingest stack on Google Cloud.
  DRY RUN BY DEFAULT: prints every command, runs nothing. Pass -Execute to run.

.DESCRIPTION
  Creates (idempotently where gcloud allows): APIs, service accounts + least-privilege IAM,
  GCS bucket (+90d/13mo lifecycle), Secret Manager secret shells, Artifact Registry repo,
  Cloud Run service (ingest), Cloud Run job (daily digest), Cloud Scheduler trigger,
  BigQuery dataset + external tables/views (from ..\bigquery\ddl.sql).
  It never writes secret VALUES: add versions yourself (see deploy\iam.md).

.PARAMETER ProjectId   Target GCP project. Firebase Hosting `run` rewrites require the Cloud Run
                       service to live in the SAME project as the Hosting site (manuel-portfolio-2026).
                       'logicflow-guardian' returned PERMISSION_DENIED in earlier checks - do not assume it.
.EXAMPLE
  .\deploy.ps1 -ProjectId manuel-portfolio-2026 -Bucket manuel-portfolio-2026-lf-telemetry          # dry run
  .\deploy.ps1 -ProjectId manuel-portfolio-2026 -Bucket manuel-portfolio-2026-lf-telemetry -Execute
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9-]{4,28}[a-z0-9]$')][string]$ProjectId,
  [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9._-]{2,62}$')][string]$Bucket,
  [string]$Region = 'us-central1',
  [string]$BqLocation = 'US',
  [string]$Dataset = 'logicflow_telemetry',
  [string]$ServiceName = 'lf-telemetry-ingest',
  [string]$JobName = 'lf-telemetry-digest',
  [string]$Repo = 'logicflow',
  [string]$DigestCron = '15 6 * * *',     # 06:15 UTC, after the UTC day rolled over; digests the previous UTC day
  [int]$MinInstances = 1,
  [int]$MaxInstances = 5,
  [string]$TrustProxyHops = '1',          # verify on first deploy, see README "Client IP"
  [switch]$Execute
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Image = "$Region-docker.pkg.dev/$ProjectId/$Repo/$ServiceName`:latest"
$IngestSa = "lf-ingest@$ProjectId.iam.gserviceaccount.com"
$DigestSa = "lf-digest@$ProjectId.iam.gserviceaccount.com"
$SchedSa = "lf-scheduler@$ProjectId.iam.gserviceaccount.com"
$script:n = 0

function Step([string]$Title, [string[]]$Cmd, [switch]$AllowFail) {
  $script:n++
  Write-Host ("`n[{0}] {1}" -f $script:n, $Title) -ForegroundColor Cyan
  Write-Host ('    ' + ($Cmd -join ' ')) -ForegroundColor DarkGray
  if (-not $Execute) { return }
  $exe = $Cmd[0]; $a = $Cmd[1..($Cmd.Length - 1)]
  & $exe @a
  if ($LASTEXITCODE -ne 0 -and -not $AllowFail) { throw "Step $($script:n) failed (exit $LASTEXITCODE): $Title" }
}

Write-Host ("Mode: {0}" -f $(if ($Execute) { 'EXECUTE (live changes)' } else { 'DRY RUN (nothing is executed)' })) -ForegroundColor Yellow
Write-Host "Project=$ProjectId Region=$Region Bucket=$Bucket Dataset=$Dataset"

try {
  if ($Execute) {
    foreach ($tool in 'gcloud', 'bq') { if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool not found on PATH" } }
    & gcloud projects describe $ProjectId --format='value(projectId)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot access project $ProjectId (PERMISSION_DENIED?). Aborting before any change." }
  }

  Step 'Enable APIs' @('gcloud', 'services', 'enable', 'run.googleapis.com', 'cloudscheduler.googleapis.com', 'secretmanager.googleapis.com', 'artifactregistry.googleapis.com', 'cloudbuild.googleapis.com', 'bigquery.googleapis.com', 'storage.googleapis.com', '--project', $ProjectId)

  foreach ($sa in @(@('lf-ingest', 'LogicFlow telemetry ingest runtime'), @('lf-digest', 'LogicFlow telemetry digest job'), @('lf-scheduler', 'LogicFlow digest scheduler'))) {
    Step "Service account $($sa[0])" @('gcloud', 'iam', 'service-accounts', 'create', $sa[0], '--display-name', $sa[1], '--project', $ProjectId) -AllowFail
  }

  Step 'Bucket (uniform access, no public access, same location as BigQuery)' @('gcloud', 'storage', 'buckets', 'create', "gs://$Bucket", '--project', $ProjectId, '--location', $BqLocation, '--uniform-bucket-level-access', '--public-access-prevention') -AllowFail
  Step 'Bucket lifecycle (raw 90d, rollups 13 months)' @('gcloud', 'storage', 'buckets', 'update', "gs://$Bucket", '--lifecycle-file', (Join-Path $PSScriptRoot 'lifecycle.json'))
  foreach ($sa in $IngestSa, $DigestSa) {
    # objectAdmin scoped to THIS bucket only: ingest writes parts, digest writes digests and purges erased installs.
    Step "Bucket IAM objectAdmin for $sa" @('gcloud', 'storage', 'buckets', 'add-iam-policy-binding', "gs://$Bucket", '--member', "serviceAccount:$sa", '--role', 'roles/storage.objectAdmin')
  }

  foreach ($s in 'lf-ingest-keys', 'lf-admin-token') {
    Step "Secret shell $s (VALUE NOT SET - add a version manually, see iam.md)" @('gcloud', 'secrets', 'create', $s, '--replication-policy', 'automatic', '--project', $ProjectId) -AllowFail
    foreach ($sa in $IngestSa, $DigestSa) {
      Step "Secret accessor $s -> $sa" @('gcloud', 'secrets', 'add-iam-policy-binding', $s, '--member', "serviceAccount:$sa", '--role', 'roles/secretmanager.secretAccessor', '--project', $ProjectId)
    }
  }

  Step 'Artifact Registry repo' @('gcloud', 'artifacts', 'repositories', 'create', $Repo, '--repository-format', 'docker', '--location', $Region, '--project', $ProjectId) -AllowFail
  Step 'Build + push image (Cloud Build)' @('gcloud', 'builds', 'submit', $Root, '--tag', $Image, '--project', $ProjectId)

  $envVars = "LF_STORAGE=gcs,LF_BUCKET=$Bucket,LF_TRUST_PROXY_HOPS=$TrustProxyHops"
  $sec = 'LF_INGEST_KEYS=lf-ingest-keys:latest,LF_ADMIN_TOKEN=lf-admin-token:latest'
  Step 'Deploy Cloud Run service (public URL; every write is HMAC-signed, secrets fail closed)' @(
    'gcloud', 'run', 'deploy', $ServiceName, '--image', $Image, '--region', $Region, '--project', $ProjectId,
    '--service-account', $IngestSa, '--allow-unauthenticated', '--port', '8080',
    '--min-instances', "$MinInstances", '--max-instances', "$MaxInstances", '--no-cpu-throttling',
    '--cpu', '1', '--memory', '512Mi', '--concurrency', '80', '--timeout', '30s',
    '--set-env-vars', $envVars, '--set-secrets', $sec)

  Step 'Create/update Cloud Run job for the daily digest' @(
    'gcloud', 'run', 'jobs', 'deploy', $JobName, '--image', $Image, '--region', $Region, '--project', $ProjectId,
    '--service-account', $DigestSa, '--command', 'node', '--args', 'src/jobs/digest.js',
    '--max-retries', '1', '--task-timeout', '600s', '--memory', '512Mi',
    '--set-env-vars', "LF_STORAGE=gcs,LF_BUCKET=$Bucket")
  Step 'Scheduler SA may run the job' @('gcloud', 'run', 'jobs', 'add-iam-policy-binding', $JobName, '--region', $Region, '--project', $ProjectId, '--member', "serviceAccount:$SchedSa", '--role', 'roles/run.invoker')
  $runUri = "https://run.googleapis.com/v2/projects/$ProjectId/locations/$Region/jobs/$JobName`:run"
  Step 'Cloud Scheduler: daily digest' @(
    'gcloud', 'scheduler', 'jobs', 'create', 'http', "$JobName-daily", '--location', $Region, '--project', $ProjectId,
    '--schedule', $DigestCron, '--time-zone', 'Etc/UTC', '--uri', $runUri, '--http-method', 'POST',
    '--oauth-service-account-email', $SchedSa) -AllowFail

  # BigQuery: render ddl.sql tokens, then run as a script.
  $ddl = (Get-Content (Join-Path $Root 'bigquery\ddl.sql') -Raw).Replace('__PROJECT__', $ProjectId).Replace('__DATASET__', $Dataset).Replace('__BUCKET__', $Bucket).Replace('__LOCATION__', $BqLocation)
  $ddlFile = Join-Path ([IO.Path]::GetTempPath()) 'lf-telemetry-ddl.rendered.sql'
  if ($Execute) { Set-Content -LiteralPath $ddlFile -Value $ddl -Encoding utf8 }
  Step 'BigQuery dataset, external tables, views (rendered ddl.sql)' @('cmd', '/c', "bq query --project_id=$ProjectId --use_legacy_sql=false --location=$BqLocation < `"$ddlFile`"")
  Write-Host '[manual] BigQuery external tables: the QUERYING user/SA also needs storage.objectViewer on the bucket (see iam.md).' -ForegroundColor Yellow

  Write-Host "`n--- Firebase Hosting rewrite (add to Website\firebase.json, api-service target, BEFORE '/v1/**') ---" -ForegroundColor Green
  Write-Host ('{ "source": "/v1/telemetry/**", "run": { "serviceId": "' + $ServiceName + '", "region": "' + $Region + '" } }')
  Write-Host "(Already added to firebase.json in the repo; deploy hosting separately. Different project => use a domain mapping / load balancer instead.)"
  if (-not $Execute) { Write-Host "`nDry run complete: $script:n steps listed, none executed. Re-run with -Execute to apply." -ForegroundColor Yellow }
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
