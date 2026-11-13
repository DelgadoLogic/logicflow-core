-- Per app version: active installs, installs with a crash, crash rate. Param: --days
SELECT appVersion,
       COUNT(DISTINCT installId) AS active_installs,
       COUNT(DISTINCT IF(type = 'crash', installId, NULL)) AS crash_installs,
       SAFE_DIVIDE(COUNT(DISTINCT IF(type = 'crash', installId, NULL)), COUNT(DISTINCT installId)) AS crash_rate,
       COUNTIF(type = 'crash') AS crash_events
FROM `__PROJECT__.__DATASET__.events`
WHERE dt >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
GROUP BY appVersion
ORDER BY appVersion DESC;
