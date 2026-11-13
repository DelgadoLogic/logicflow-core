-- Driver versions across baselines; look for outliers. Param: --days (unused, baselines are latest-per-install)
SELECT driver_class, vendor, driver_name, driver_version, driver_date, installs
FROM `__PROJECT__.__DATASET__.driver_index`
ORDER BY installs DESC
LIMIT 100;
