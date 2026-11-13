-- Crash groups first seen in a version AFTER an older version already had them, or still crashing in a newer version.
-- Per-version regression tracking straight from the crash_groups view. Param: --days
SELECT g.fingerprint, g.exception_type, g.top_frames,
       ARRAY(SELECT AS STRUCT v.version, v.events, v.installs FROM UNNEST(g.by_version) v ORDER BY v.first_seen) AS versions,
       ARRAY_LENGTH(g.by_version) AS version_count, g.last_seen
FROM `__PROJECT__.__DATASET__.crash_groups` g
WHERE g.kind = 'crash' AND ARRAY_LENGTH(g.by_version) > 1
  AND g.last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
ORDER BY g.last_seen DESC
LIMIT 50;
