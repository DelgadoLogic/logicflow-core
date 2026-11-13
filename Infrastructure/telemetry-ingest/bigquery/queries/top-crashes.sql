-- Top crash groups in the last N days (default 7). Param: --days
SELECT fingerprint, ANY_VALUE(payload.exceptionType) AS exception_type, COUNT(*) AS events,
       COUNT(DISTINCT installId) AS installs, MIN(ts) AS first_seen, MAX(ts) AS last_seen,
       ARRAY_AGG(DISTINCT appVersion ORDER BY appVersion) AS versions
FROM `__PROJECT__.__DATASET__.events`
WHERE type = 'crash' AND dt >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
GROUP BY fingerprint
ORDER BY installs DESC, events DESC
LIMIT 25;
