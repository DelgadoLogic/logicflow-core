-- Compliance check: must always return 0 rows. Any row is an erased install still visible in raw storage.
SELECT COUNT(*) AS leaked_rows
FROM `__PROJECT__.__DATASET__.events_raw` e
JOIN `__PROJECT__.__DATASET__.erasures_raw` x ON x.installIdHash = TO_HEX(SHA256(e.installId))
HAVING COUNT(*) > 0;
