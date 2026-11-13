-- Scan statistics per scan type. Param: --days
SELECT payload.scanType AS scan_type, COUNT(*) AS scans,
       APPROX_QUANTILES(payload.durationMs, 100)[OFFSET(50)] AS p50_ms,
       APPROX_QUANTILES(payload.durationMs, 100)[OFFSET(95)] AS p95_ms,
       AVG(payload.healthScore) AS avg_health_score,
       SUM(payload.bytesReclaimable) AS bytes_reclaimable
FROM `__PROJECT__.__DATASET__.events`
WHERE type = 'scan' AND dt >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
GROUP BY scan_type
ORDER BY scans DESC;
