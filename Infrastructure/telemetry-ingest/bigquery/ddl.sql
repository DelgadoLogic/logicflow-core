-- LogicFlow telemetry - BigQuery DDL (schema v1)            NOT executed by this repo.
--
-- Tokens replaced by deploy/deploy.ps1 (or by hand):
--   __PROJECT__  GCP project that owns the dataset
--   __DATASET__  dataset name (default: logicflow_telemetry)
--   __BUCKET__   GCS bucket holding v1/events/... (LF_BUCKET)
--   __LOCATION__ dataset/bucket location, must match (e.g. US)
--
-- Design:
--   * Raw events live in GCS as gzip NDJSON (v1/events/dt=YYYY-MM-DD/type=<t>/part-*.ndjson.gz).
--   * `events_raw` is an EXTERNAL table over those files. No hive partitioning: the file
--     already contains `dt` and `type` columns and hive keys would collide with them.
--     Each row carries `dt` (UTC date of ingest) and the view filters on it; add a
--     `_FILE_NAME LIKE '%/dt=2026-10-01/%'` predicate in ad-hoc queries to prune files.
--   * `erasures_raw` is an external table over tombstones (sha256 of the installId only).
--   * `events` view = de-duplicated by eventId (ingest dedupe is per instance only),
--     minus erased installs. All other views read from `events`.
--   * Retention: GCS lifecycle deletes raw objects after 90 days; views therefore only
--     ever show <= 90 days. Rollups (13 months) and crash groups are in GCS JSON
--     (v1/rollups, v1/crash_groups) and can be loaded with `bq load` if you want SQL over them.
--     If you materialise any table from `events`, include installId only if you also
--     run the erasure DELETE at the bottom of this file.

CREATE SCHEMA IF NOT EXISTS `__PROJECT__.__DATASET__`
OPTIONS (location = '__LOCATION__', description = 'LogicFlow telemetry (schema v1). Raw retention 90 days.');

-- ---------------------------------------------------------------- raw external tables
CREATE OR REPLACE EXTERNAL TABLE `__PROJECT__.__DATASET__.events_raw` (
  schema INT64,
  eventId STRING,
  type STRING,
  ts TIMESTAMP,
  installId STRING,
  appVersion STRING,
  osBuild STRING,
  arch STRING,
  tier STRING,
  region STRING,
  receivedAt TIMESTAMP,
  consent STRING,
  fingerprint STRING,
  ingestId STRING,
  dt DATE,
  payload STRUCT<
    -- crash / error
    exceptionType STRING,
    message STRING,
    hresult STRING,
    frames ARRAY<STRING>,
    inner ARRAY<STRUCT<exceptionType STRING, message STRING>>,
    component STRING,
    isFatal BOOL,
    uptimeSec INT64,
    code STRING,
    severity STRING,
    -- usage
    feature STRING,
    action STRING,
    durationMs INT64,
    count INT64,
    props ARRAY<STRUCT<k STRING, v STRING>>,
    -- scan
    scanType STRING,
    itemsFound INT64,
    bytesReclaimable INT64,
    healthScore INT64,
    modulesRun ARRAY<STRING>,
    issues ARRAY<STRUCT<id STRING, count INT64>>,
    -- baseline
    windows STRUCT<edition STRING, displayVersion STRING, ubr INT64>,
    hardware STRUCT<
      cpuName STRING, cpuCores INT64, ramGb FLOAT64,
      gpus ARRAY<STRUCT<vendor STRING, name STRING, driverVersion STRING, driverDate STRING>>,
      biosVendor STRING, biosVersion STRING, boardVendor STRING, boardModel STRING,
      diskTypes ARRAY<STRING>>,
    drivers ARRAY<STRUCT<class STRING, vendor STRING, name STRING, version STRING, date STRING, hwidClass STRING>>,
    kbs ARRAY<STRING>,
    securityProducts ARRAY<STRING>,
    servicesRunning INT64
  >
)
OPTIONS (
  format = 'NEWLINE_DELIMITED_JSON',
  compression = 'GZIP',
  uris = ['gs://__BUCKET__/v1/events/*'],
  ignore_unknown_values = true,
  max_staleness = INTERVAL 15 MINUTE,
  metadata_cache_mode = 'AUTOMATIC'
);

CREATE OR REPLACE EXTERNAL TABLE `__PROJECT__.__DATASET__.erasures_raw` (
  installIdHash STRING,
  requestedAt TIMESTAMP,
  status STRING
)
OPTIONS (
  format = 'NEWLINE_DELIMITED_JSON',
  uris = ['gs://__BUCKET__/v1/erasures/*.json'],
  ignore_unknown_values = true
);

-- ---------------------------------------------------------------- views
-- events: dedupe by eventId (first receipt wins) and honour right-to-erasure.
CREATE OR REPLACE VIEW `__PROJECT__.__DATASET__.events` AS
SELECT * EXCEPT (_rn)
FROM (
  SELECT
    e.*,
    ROW_NUMBER() OVER (PARTITION BY e.eventId ORDER BY e.receivedAt) AS _rn
  FROM `__PROJECT__.__DATASET__.events_raw` e
  WHERE NOT EXISTS (
    SELECT 1 FROM `__PROJECT__.__DATASET__.erasures_raw` x
    WHERE x.installIdHash = TO_HEX(SHA256(e.installId))
  )
)
WHERE _rn = 1;

-- crash_groups: one row per fingerprint, per app version breakdown, no installIds exposed.
CREATE OR REPLACE VIEW `__PROJECT__.__DATASET__.crash_groups` AS
WITH per_version AS (
  SELECT
    fingerprint, type AS kind, appVersion AS version,
    ANY_VALUE(payload.exceptionType) AS exception_type,
    ANY_VALUE(ARRAY_TO_STRING(ARRAY(SELECT f FROM UNNEST(payload.frames) f WITH OFFSET o ORDER BY o LIMIT 3), ' | ')) AS top_frames,
    MIN(ts) AS first_seen, MAX(ts) AS last_seen,
    COUNT(*) AS events, COUNT(DISTINCT installId) AS installs
  FROM `__PROJECT__.__DATASET__.events`
  WHERE type IN ('crash', 'error') AND fingerprint IS NOT NULL
  GROUP BY fingerprint, kind, version
)
SELECT
  fingerprint, kind,
  ANY_VALUE(exception_type) AS exception_type,
  ANY_VALUE(top_frames) AS top_frames,
  MIN(first_seen) AS first_seen,
  MAX(last_seen) AS last_seen,
  SUM(events) AS events,
  SUM(installs) AS installs_sum_over_versions,
  ARRAY_AGG(STRUCT(version, events, installs, first_seen, last_seen) ORDER BY first_seen) AS by_version
FROM per_version
GROUP BY fingerprint, kind;

-- baseline_devices: latest baseline per install (pseudonymous; deleted via /delete).
CREATE OR REPLACE VIEW `__PROJECT__.__DATASET__.baseline_devices` AS
SELECT * EXCEPT (_rn)
FROM (
  SELECT
    installId, appVersion, osBuild, arch, tier, region, ts,
    payload.windows AS windows,
    payload.hardware AS hardware,
    payload.drivers AS drivers,
    payload.kbs AS kbs,
    payload.securityProducts AS security_products,
    payload.servicesRunning AS services_running,
    ROW_NUMBER() OVER (PARTITION BY installId ORDER BY ts DESC) AS _rn
  FROM `__PROJECT__.__DATASET__.events`
  WHERE type = 'baseline'
)
WHERE _rn = 1;

-- driver_index: driver inventory fleet-wide (how many installs run which driver version).
CREATE OR REPLACE VIEW `__PROJECT__.__DATASET__.driver_index` AS
SELECT
  d.class AS driver_class,
  d.vendor,
  d.name AS driver_name,
  d.version AS driver_version,
  d.date AS driver_date,
  d.hwidClass AS hwid_class,
  COUNT(DISTINCT b.installId) AS installs
FROM `__PROJECT__.__DATASET__.baseline_devices` b, UNNEST(b.drivers) d
GROUP BY driver_class, vendor, driver_name, driver_version, driver_date, hwid_class;

-- ---------------------------------------------------------------- erasure for materialised copies
-- Only needed if you copy `events` rows into a native table. Run with the hash of the installId
-- (never the raw id) taken from v1/erasures/<hash>.json:
--
--   DELETE FROM `__PROJECT__.__DATASET__.events_materialised`
--   WHERE TO_HEX(SHA256(installId)) = @installIdHash;
