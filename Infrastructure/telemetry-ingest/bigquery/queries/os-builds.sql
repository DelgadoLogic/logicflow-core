-- OS build distribution (and crash share). Param: --days
SELECT osBuild, arch, COUNT(DISTINCT installId) AS installs,
       COUNT(DISTINCT IF(type = 'crash', installId, NULL)) AS crash_installs
FROM `__PROJECT__.__DATASET__.events`
WHERE dt >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
GROUP BY osBuild, arch
ORDER BY installs DESC
LIMIT 50;
