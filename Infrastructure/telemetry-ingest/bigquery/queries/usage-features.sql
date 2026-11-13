-- Feature usage across installs with standard or extended consent. Param: --days
SELECT payload.feature AS feature, payload.action AS action, COUNT(*) AS events, COUNT(DISTINCT installId) AS installs
FROM `__PROJECT__.__DATASET__.events`
WHERE type = 'usage' AND dt >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
GROUP BY feature, action
ORDER BY installs DESC, events DESC
LIMIT 100;
