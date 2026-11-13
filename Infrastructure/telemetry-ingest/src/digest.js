'use strict';

const { PREFIX, utcDate, addDays } = require('./eventStore');
const { purgePendingErasures } = require('./erasure');

const DIGEST_SCHEMA = 1;

// ---------------------------------------------------------------- helpers
function cmpVersion(a, b) {
  const pa = String(a).split(/[.+-]/).map((x) => Number.parseInt(x, 10) || 0);
  const pb = String(b).split(/[.+-]/).map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function inc(obj, key, n = 1) {
  obj[key] = (obj[key] || 0) + n;
}

function topN(obj, n = 10) {
  return Object.entries(obj)
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));
}

function daysBetween(a, b) {
  return Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 86400000);
}

function ramBucket(gb) {
  if (typeof gb !== 'number') return 'unknown';
  if (gb < 4) return '<4';
  if (gb < 8) return '4-7';
  if (gb < 16) return '8-15';
  if (gb < 32) return '16-31';
  return '32+';
}

// ------------------------------------------------------------ aggregation
async function aggregateDay(store, date) {
  const agg = {
    events: 0,
    byType: {},
    byTier: {},
    byRegion: {},
    byArch: {},
    byConsent: {},
    installs: new Set(),
    versions: {}, // v -> {events, installs:Set, crashes, crashInstalls:Set}
    osBuilds: {}, // os -> {events, crashes, crashInstalls:Set}
    crashGroups: {}, // fp -> group
    errorGroups: {},
    scan: { count: 0, durationMs: 0, durationN: 0, health: 0, healthN: 0, itemsFound: 0, bytesReclaimable: 0, issues: {}, modules: {}, types: {} },
    usage: { count: 0, features: {}, actions: {} },
    baseline: { count: 0, installs: new Set(), gpuVendors: {}, gpuDrivers: {}, ram: {}, windows: {}, driverClasses: {}, securityProducts: {} },
  };

  for await (const ev of store.readEvents(date, undefined)) {
    agg.events += 1;
    inc(agg.byType, ev.type);
    inc(agg.byTier, ev.tier);
    inc(agg.byRegion, ev.region);
    inc(agg.byArch, ev.arch);
    inc(agg.byConsent, ev.consent || 'unknown');
    agg.installs.add(ev.installId);

    const v = (agg.versions[ev.appVersion] ||= { events: 0, installs: new Set(), crashes: 0, crashInstalls: new Set() });
    v.events += 1;
    v.installs.add(ev.installId);
    const os = (agg.osBuilds[ev.osBuild] ||= { events: 0, crashes: 0, crashInstalls: new Set() });
    os.events += 1;

    const p = ev.payload || {};
    if (ev.type === 'crash' || ev.type === 'error') {
      const isCrash = ev.type === 'crash';
      if (isCrash) {
        v.crashes += 1;
        v.crashInstalls.add(ev.installId);
        os.crashes += 1;
        os.crashInstalls.add(ev.installId);
      }
      const fp = ev.fingerprint || 'unknown';
      const table = isCrash ? agg.crashGroups : agg.errorGroups;
      const g = (table[fp] ||= {
        fingerprint: fp,
        kind: ev.type,
        title: isCrash ? p.exceptionType : `${p.component}:${p.code}`,
        exceptionType: p.exceptionType,
        code: p.code,
        component: p.component,
        message: p.message,
        hresult: p.hresult,
        frames: (p.frames || []).slice(0, 8),
        count: 0,
        installs: new Set(),
        versions: {},
        osBuilds: {},
      });
      g.count += 1;
      g.installs.add(ev.installId);
      inc(g.versions, ev.appVersion);
      inc(g.osBuilds, ev.osBuild);
    } else if (ev.type === 'scan') {
      const s = agg.scan;
      s.count += 1;
      inc(s.types, p.scanType);
      if (typeof p.durationMs === 'number') {
        s.durationMs += p.durationMs;
        s.durationN += 1;
      }
      if (typeof p.healthScore === 'number') {
        s.health += p.healthScore;
        s.healthN += 1;
      }
      s.itemsFound += p.itemsFound || 0;
      s.bytesReclaimable += p.bytesReclaimable || 0;
      for (const i of p.issues || []) inc(s.issues, i.id, i.count || 1);
      for (const m of p.modulesRun || []) inc(s.modules, m);
    } else if (ev.type === 'usage') {
      agg.usage.count += 1;
      inc(agg.usage.features, p.feature);
      inc(agg.usage.actions, `${p.feature}/${p.action}`, p.count || 1);
    } else if (ev.type === 'baseline') {
      const b = agg.baseline;
      b.count += 1;
      b.installs.add(ev.installId);
      const hw = p.hardware || {};
      for (const g of hw.gpus || []) {
        inc(b.gpuVendors, g.vendor || 'unknown');
        if (g.name && g.driverVersion) inc(b.gpuDrivers, `${g.vendor || '?'} ${g.name} @ ${g.driverVersion}`);
      }
      inc(b.ram, ramBucket(hw.ramGb));
      if (p.windows) inc(b.windows, `${p.windows.edition || '?'} ${p.windows.displayVersion || ''}`.trim());
      for (const d of p.drivers || []) inc(b.driverClasses, d.class || 'unknown');
      for (const s of p.securityProducts || []) inc(b.securityProducts, s);
    }
  }
  return agg;
}

function serializeAgg(agg, date) {
  const versions = {};
  for (const [k, v] of Object.entries(agg.versions)) {
    versions[k] = { events: v.events, installs: v.installs.size, crashes: v.crashes, crashInstalls: v.crashInstalls.size };
  }
  const osBuilds = {};
  for (const [k, v] of Object.entries(agg.osBuilds)) osBuilds[k] = { events: v.events, crashes: v.crashes, crashInstalls: v.crashInstalls.size };
  const groups = (t) =>
    Object.values(t).map((g) => ({ fingerprint: g.fingerprint, kind: g.kind, title: g.title, count: g.count, installs: g.installs.size, versions: g.versions, osBuilds: g.osBuilds }));
  return {
    schema: 1,
    date,
    events: agg.events,
    activeInstalls: agg.installs.size,
    byType: agg.byType,
    byTier: agg.byTier,
    byRegion: agg.byRegion,
    byArch: agg.byArch,
    byConsent: agg.byConsent,
    versions,
    osBuilds,
    crashGroups: groups(agg.crashGroups),
    errorGroups: groups(agg.errorGroups),
    scan: { count: agg.scan.count },
    usage: { count: agg.usage.count },
    baseline: { count: agg.baseline.count },
  };
}

// ------------------------------------------------------------ crash state
async function updateCrashState(store, agg, date) {
  const key = `${PREFIX.crashGroups}/state.json`;
  const state = (await store.getJson(key)) || { schema: 1, updatedAt: null, processedDates: [], groups: {} };
  const triage = (await store.getJson(`${PREFIX.triage}/crash_groups.json`)) || {};
  const alreadyProcessed = state.processedDates.includes(date);

  if (!alreadyProcessed) {
    for (const g of [...Object.values(agg.crashGroups), ...Object.values(agg.errorGroups)]) {
      const dayVersions = Object.keys(g.versions).sort(cmpVersion);
      let s = state.groups[g.fingerprint];
      if (!s) {
        s = state.groups[g.fingerprint] = {
          fingerprint: g.fingerprint,
          kind: g.kind,
          title: g.title,
          component: g.component || null,
          hresult: g.hresult || null,
          sampleMessage: g.message || null,
          sampleFrames: g.frames,
          firstSeen: date,
          firstSeenVersion: dayVersions[0],
          lastSeen: date,
          lastSeenVersion: dayVersions[dayVersions.length - 1],
          totalEvents: 0,
          versions: {},
          osBuilds: {},
          reappearances: [],
        };
      } else {
        const dormant = daysBetween(s.lastSeen, date);
        if (dormant >= 14) {
          s.reappearances.push({ date, dormantDays: dormant, version: dayVersions[dayVersions.length - 1] });
          s.reappearances = s.reappearances.slice(-10);
        }
        if (cmpVersion(dayVersions[dayVersions.length - 1], s.lastSeenVersion) > 0) s.lastSeenVersion = dayVersions[dayVersions.length - 1];
        if (date > s.lastSeen) s.lastSeen = date;
      }
      s.totalEvents += g.count;
      for (const [ver, n] of Object.entries(g.versions)) {
        const e = (s.versions[ver] ||= { events: 0, firstSeen: date, lastSeen: date });
        e.events += n;
        if (date > e.lastSeen) e.lastSeen = date;
      }
      for (const [os, n] of Object.entries(g.osBuilds)) inc(s.osBuilds, os, n);
      // cap osBuilds to the 25 most frequent to keep state small
      if (Object.keys(s.osBuilds).length > 25) {
        s.osBuilds = Object.fromEntries(Object.entries(s.osBuilds).sort((a, b) => b[1] - a[1]).slice(0, 25));
      }
    }
    state.processedDates = [...state.processedDates, date].slice(-400);
    state.updatedAt = new Date().toISOString();
  }
  for (const [fp, t] of Object.entries(triage)) if (state.groups[fp]) state.groups[fp].triage = t;
  if (!alreadyProcessed || Object.keys(triage).length) await store.putJson(key, state);
  return { state, alreadyProcessed };
}

// ------------------------------------------------------------ anomalies
async function loadRollups(store, date, days = 7) {
  const out = [];
  for (let i = 1; i <= days; i++) {
    const r = await store.getJson(`${PREFIX.rollups}/dt=${addDays(date, -i)}.json`);
    if (r) out.push(r);
  }
  return out;
}

function mean(arr) {
  return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
}

function detectAnomalies({ day, prior, ingest, newCrashGroups, topCrash, versionHealth }) {
  const a = [];
  const add = (severity, code, message, data = {}) => a.push({ severity, code, message, data });

  if (day.events === 0) add('info', 'no_events', 'No events were stored for this date (no traffic, outage, or all rejected).');

  if (prior.length >= 3) {
    for (const t of ['crash', 'error', 'scan', 'usage', 'baseline']) {
      const m = mean(prior.map((r) => (r.byType && r.byType[t]) || 0));
      const today = day.byType[t] || 0;
      if (today > m * 3 && today > m + 20) add('warn', 'volume_spike', `${t} events ${today} vs 7-day mean ${m.toFixed(1)}`, { type: t, today, mean: m });
      if (m >= 50 && today < m * 0.3) add('warn', 'volume_drop', `${t} events ${today} vs 7-day mean ${m.toFixed(1)} (possible client/ingest outage)`, { type: t, today, mean: m });
    }
    const mi = mean(prior.map((r) => r.activeInstalls || 0));
    if (mi >= 20 && day.activeInstalls < mi * 0.4) add('warn', 'active_installs_drop', `Active installs ${day.activeInstalls} vs mean ${mi.toFixed(1)}`, { today: day.activeInstalls, mean: mi });
  }
  const crashes = day.byType.crash || 0;
  if (newCrashGroups.length >= 10) add('warn', 'new_group_burst', `${newCrashGroups.length} new crash groups in one day`, { count: newCrashGroups.length });
  if (crashes >= 10 && topCrash && topCrash.count / crashes >= 0.5) {
    add('warn', 'dominant_group', `Group ${topCrash.fingerprint.slice(0, 12)} is ${(100 * topCrash.count / crashes).toFixed(0)}% of crashes`, { fingerprint: topCrash.fingerprint });
  }
  const totalCrashInstalls = Object.values(day.versions).reduce((s, v) => s + v.crashInstalls, 0);
  for (const v of versionHealth) {
    const otherInstalls = day.activeInstalls - v.installs;
    const othersRate = otherInstalls > 0 ? (totalCrashInstalls - (day.versions[v.version] ? day.versions[v.version].crashInstalls : 0)) / otherInstalls : 0;
    if (v.installs >= 10 && v.crashRate >= 0.15 && v.crashRate >= othersRate * 2) add('alert', 'version_crash_rate', `v${v.version}: ${(v.crashRate * 100).toFixed(1)}% of active installs crashed`, { version: v.version, crashRate: v.crashRate, othersRate });
  }
  const accepted = ingest.accepted;
  const rejected = ingest.rejected;
  if (accepted + rejected >= 50 && rejected / (accepted + rejected) > 0.2) add('warn', 'reject_rate_high', `${(100 * rejected / (accepted + rejected)).toFixed(0)}% of submitted events were rejected`, { accepted, rejected, reasons: ingest.rejectReasons });
  if ((ingest.httpStatus['401'] || 0) >= 20) add('warn', 'invalid_signatures', `${ingest.httpStatus['401']} requests failed signature verification (rotated/leaked key, or probing)`, {});
  if ((ingest.httpStatus['429'] || 0) >= 20) add('info', 'rate_limited', `${ingest.httpStatus['429']} requests were rate limited`, {});
  return a;
}

function mergeStats(docs) {
  const t = { requests: 0, accepted: 0, rejected: 0, bytesIn: 0, byEndpoint: {}, byType: {}, rejectReasons: {}, httpStatus: {} };
  for (const d of docs) {
    const c = d.counters || {};
    t.requests += c.requests || 0;
    t.accepted += c.accepted || 0;
    t.rejected += c.rejected || 0;
    t.bytesIn += c.bytesIn || 0;
    for (const k of ['byEndpoint', 'byType', 'rejectReasons', 'httpStatus']) for (const [kk, vv] of Object.entries(c[k] || {})) inc(t[k], kk, vv);
  }
  return t;
}

// ------------------------------------------------------------ generator
async function generateDigest(store, cfg, { date, now = new Date() } = {}) {
  const day = date || addDays(utcDate(now), -1);

  // Housekeeping first: honour any pending right-to-erasure before reading data.
  const erasures = await purgePendingErasures(store, { today: utcDate(now) });

  const agg = await aggregateDay(store, day);
  const rollup = serializeAgg(agg, day);
  await store.putJson(`${PREFIX.rollups}/dt=${day}.json`, rollup);
  const prior = await loadRollups(store, day, 7);
  const statsDocs = await store.readStats(day);
  const ingest = mergeStats(statsDocs);

  const { state, alreadyProcessed } = await updateCrashState(store, agg, day);

  // ---- crash groups
  const crashList = Object.values(agg.crashGroups).sort((a, b) => b.count - a.count);
  const crashTotal = agg.byType.crash || 0;
  const present = (g) => state.groups[g.fingerprint] || {};
  const row = (g) => ({
    fingerprint: g.fingerprint,
    kind: g.kind,
    title: g.title,
    count: g.count,
    installs: g.installs.size,
    versions: g.versions,
    topOsBuilds: topN(g.osBuilds, 3),
    hresult: g.hresult || null,
    component: g.component || null,
    sampleMessage: g.message || null,
    sampleFrames: g.frames.slice(0, 5),
    firstSeen: present(g).firstSeen || day,
    firstSeenVersion: present(g).firstSeenVersion || null,
    triage: present(g).triage || null,
  });
  const newCrashGroups = [...crashList, ...Object.values(agg.errorGroups)].filter((g) => present(g).firstSeen === day).sort((a, b) => b.count - a.count);

  // ---- regressions
  const regressions = [];
  for (const g of [...crashList, ...Object.values(agg.errorGroups)]) {
    const s = present(g);
    const dayVers = Object.keys(g.versions).sort(cmpVersion);
    if (s.triage && s.triage.status === 'fixed' && s.triage.fixedIn) {
      const bad = dayVers.filter((v) => cmpVersion(v, s.triage.fixedIn) >= 0);
      if (bad.length) regressions.push({ type: 'fixed_but_seen', fingerprint: g.fingerprint, title: g.title, fixedIn: s.triage.fixedIn, seenInVersions: bad, count: bad.reduce((n, v) => n + g.versions[v], 0) });
    }
    const reapp = (s.reappearances || []).find((r) => r.date === day);
    if (reapp) regressions.push({ type: 'reappeared', fingerprint: g.fingerprint, title: g.title, dormantDays: reapp.dormantDays, version: reapp.version, count: g.count });
    if (s.versions && s.firstSeen !== day) {
      const fresh = dayVers.filter((v) => s.versions[v] && s.versions[v].firstSeen === day);
      if (fresh.length) regressions.push({ type: 'new_in_version', fingerprint: g.fingerprint, title: g.title, versions: fresh, firstSeen: s.firstSeen, firstSeenVersion: s.firstSeenVersion, count: fresh.reduce((n, v) => n + g.versions[v], 0) });
    }
  }

  // ---- version health & OS builds
  const versionHealth = Object.entries(agg.versions)
    .map(([version, v]) => ({
      version,
      events: v.events,
      installs: v.installs.size,
      crashes: v.crashes,
      crashInstalls: v.crashInstalls.size,
      crashRate: v.installs.size ? v.crashInstalls.size / v.installs.size : 0,
    }))
    .sort((a, b) => cmpVersion(b.version, a.version));
  const affectedOsBuilds = Object.entries(agg.osBuilds)
    .filter(([, v]) => v.crashes > 0)
    .map(([osBuild, v]) => ({ osBuild, events: v.events, crashes: v.crashes, crashInstalls: v.crashInstalls.size }))
    .sort((a, b) => b.crashes - a.crashes)
    .slice(0, 10);

  const anomalies = detectAnomalies({ day: rollup, prior, ingest, newCrashGroups: newCrashGroups.filter((g) => g.kind === 'crash'), topCrash: crashList[0], versionHealth });

  // ---- prompts for the investigating agent
  const prompts = [];
  for (const g of crashList.slice(0, 3)) {
    prompts.push(`Investigate crash group ${g.fingerprint.slice(0, 12)} (${g.title}; ${g.count} events, ${g.installs.size} installs; versions ${Object.keys(g.versions).join(', ')}). Locate the throwing code from frames [${g.frames.slice(0, 3).join(' | ')}], explain the likely root cause and propose a fix plus a regression test.`);
  }
  for (const r of regressions.slice(0, 3)) {
    prompts.push(`Regression (${r.type}) for group ${r.fingerprint.slice(0, 12)} "${r.title}": diff the code between the last good version and the version(s) where it now appears and identify what reintroduced it.`);
  }
  for (const an of anomalies.filter((x) => x.severity !== 'info').slice(0, 3)) {
    prompts.push(`Anomaly ${an.code}: ${an.message}. Query BigQuery (see tools/telemetry-query: queries "version-health" and "ingest-health") to confirm and propose causes.`);
  }
  if (prompts.length === 0) prompts.push('No actionable findings. Review "scan" and "usage" sections for product-direction signals; verify ingest health.');

  const scan = agg.scan;
  const json = {
    digestSchema: DIGEST_SCHEMA,
    date: day,
    generatedAt: now.toISOString(),
    summary: {
      events: agg.events,
      activeInstalls: agg.installs.size,
      crashEvents: crashTotal,
      distinctCrashGroups: crashList.length,
      newCrashGroups: newCrashGroups.length,
      regressions: regressions.length,
      anomalies: anomalies.length,
      accepted: ingest.accepted,
      rejected: ingest.rejected,
    },
    ingestHealth: { ...ingest, statsFiles: statsDocs.length, erasuresProcessed: erasures.length },
    breakdown: { byType: agg.byType, byTier: agg.byTier, byArch: agg.byArch, byConsent: agg.byConsent, topRegions: topN(agg.byRegion, 10) },
    newCrashGroups: newCrashGroups.slice(0, 10).map(row),
    regressions: regressions.slice(0, 20),
    topCrashGroups: crashList.slice(0, 10).map(row),
    topErrorGroups: Object.values(agg.errorGroups).sort((a, b) => b.count - a.count).slice(0, 10).map(row),
    versionHealth,
    affectedOsBuilds,
    scan: {
      count: scan.count,
      avgDurationMs: scan.durationN ? Math.round(scan.durationMs / scan.durationN) : null,
      avgHealthScore: scan.healthN ? Number((scan.health / scan.healthN).toFixed(1)) : null,
      itemsFound: scan.itemsFound,
      bytesReclaimable: scan.bytesReclaimable,
      byType: topN(scan.types, 10),
      topIssues: topN(scan.issues, 10),
      topModules: topN(scan.modules, 10),
    },
    usage: { count: agg.usage.count, topFeatures: topN(agg.usage.features, 10), topActions: topN(agg.usage.actions, 10) },
    baseline: {
      count: agg.baseline.count,
      devices: agg.baseline.installs.size,
      gpuVendors: topN(agg.baseline.gpuVendors, 10),
      topGpuDrivers: topN(agg.baseline.gpuDrivers, 10),
      ram: topN(agg.baseline.ram, 10),
      windows: topN(agg.baseline.windows, 10),
      driverClasses: topN(agg.baseline.driverClasses, 10),
      securityProducts: topN(agg.baseline.securityProducts, 10),
    },
    anomalies,
    suggestedPrompts: prompts,
    crashStateUpdated: !alreadyProcessed,
    paths: {
      rollup: `${PREFIX.rollups}/dt=${day}.json`,
      crashGroupState: `${PREFIX.crashGroups}/state.json`,
      rawEvents: `${PREFIX.events}/dt=${day}/`,
      dictionary: 'v1/README.md',
    },
  };

  const md = renderMarkdown(json);

  // ---- write
  await store.putJson(`${PREFIX.digests}/${day}.json`, json);
  await store.putText(`${PREFIX.digests}/${day}.md`, md);
  const latest = await store.getJson(`${PREFIX.digests}/latest.json`);
  if (!latest || latest.date <= day) {
    await store.putJson(`${PREFIX.digests}/latest.json`, json);
    await store.putText(`${PREFIX.digests}/latest.md`, md);
  }
  await store.putText('v1/README.md', DICTIONARY_MD);

  if (store.storage.kind === 'fs') await enforceRetention(store, cfg, utcDate(now));

  return { json, markdown: md, summary: json.summary };
}

/** Local/emulator retention (GCS uses bucket lifecycle rules instead - see deploy/lifecycle.json). */
async function enforceRetention(store, cfg, today) {
  const cutoffRaw = addDays(today, -cfg.rawRetentionDays);
  const cutoffRoll = addDays(today, -cfg.rollupRetentionDays);
  for (const prefix of [PREFIX.events, PREFIX.stats]) {
    for (const key of await store.storage.list(prefix)) {
      const m = key.match(/dt=(\d{4}-\d{2}-\d{2})/);
      if (m && m[1] < cutoffRaw) await store.storage.delete(key);
    }
  }
  for (const key of await store.storage.list(PREFIX.rollups)) {
    const m = key.match(/dt=(\d{4}-\d{2}-\d{2})/);
    if (m && m[1] < cutoffRoll) await store.storage.delete(key);
  }
}

// ------------------------------------------------------------ markdown
function table(headers, rows) {
  if (!rows.length) return '_none_\n';
  const esc = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  return `| ${headers.join(' | ')} |\n| ${headers.map(() => '---').join(' | ')} |\n${rows.map((r) => `| ${r.map(esc).join(' | ')} |`).join('\n')}\n`;
}

function renderMarkdown(d) {
  const s = d.summary;
  const L = [];
  L.push(`# LogicFlow telemetry digest — ${d.date}`);
  L.push('');
  L.push(`_Generated ${d.generatedAt} · digest schema ${d.digestSchema} · event schema v1 · all data pseudonymous, PII-scrubbed_`);
  L.push('');
  L.push('## TL;DR');
  L.push(`- Events stored: **${s.events}** from **${s.activeInstalls}** active installs`);
  L.push(`- Crashes: **${s.crashEvents}** events in **${s.distinctCrashGroups}** groups (**${s.newCrashGroups} new**)`);
  L.push(`- Regressions flagged: **${s.regressions}** · Anomalies: **${s.anomalies}**`);
  L.push(`- Ingest: accepted **${s.accepted}**, rejected **${s.rejected}**`);
  L.push('');

  L.push('## Anomalies');
  L.push(d.anomalies.length ? d.anomalies.map((a) => `- **[${a.severity}] ${a.code}** — ${a.message}`).join('\n') : '_none_');
  L.push('');

  L.push('## Top new crash groups');
  L.push(table(['fingerprint', 'type / title', 'events', 'installs', 'versions', 'first seen', 'top frame'], d.newCrashGroups.map((g) => [g.fingerprint.slice(0, 12), g.title, g.count, g.installs, Object.keys(g.versions).join(', '), `${g.firstSeen} (v${g.firstSeenVersion})`, g.sampleFrames[0] || ''])));

  L.push('## Per-version regressions');
  L.push(table(['type', 'fingerprint', 'title', 'detail', 'events'], d.regressions.map((r) => [r.type, r.fingerprint.slice(0, 12), r.title, r.type === 'fixed_but_seen' ? `fixed in ${r.fixedIn}, seen in ${r.seenInVersions.join(', ')}` : r.type === 'reappeared' ? `dormant ${r.dormantDays}d, back in v${r.version}` : `new in ${r.versions.join(', ')} (first seen ${r.firstSeen} v${r.firstSeenVersion})`, r.count])));

  L.push('## Top crash groups (today)');
  L.push(table(['fingerprint', 'type / title', 'events', 'installs', 'versions', 'triage'], d.topCrashGroups.map((g) => [g.fingerprint.slice(0, 12), g.title, g.count, g.installs, Object.keys(g.versions).join(', '), g.triage ? `${g.triage.status}${g.triage.fixedIn ? ' in ' + g.triage.fixedIn : ''}` : 'open'])));

  L.push('## Version health');
  L.push(table(['version', 'active installs', 'events', 'crashes', 'installs crashed', 'crash rate'], d.versionHealth.map((v) => [v.version, v.installs, v.events, v.crashes, v.crashInstalls, `${(v.crashRate * 100).toFixed(1)}%`])));

  L.push('## Affected OS builds (crashes)');
  L.push(table(['os build', 'crashes', 'installs crashed', 'events'], d.affectedOsBuilds.map((o) => [o.osBuild, o.crashes, o.crashInstalls, o.events])));

  L.push('## Scans');
  L.push(`- Scans: **${d.scan.count}** · avg health score: **${d.scan.avgHealthScore ?? 'n/a'}** · avg duration: **${d.scan.avgDurationMs ?? 'n/a'} ms** · reclaimable: **${d.scan.bytesReclaimable}** bytes`);
  L.push('');
  L.push(table(['top issue id', 'count'], d.scan.topIssues.map((i) => [i.key, i.count])));

  L.push('## Usage');
  L.push(table(['feature', 'events'], d.usage.topFeatures.map((i) => [i.key, i.count])));

  L.push('## Baseline fleet snapshot');
  L.push(`- Baselines received: **${d.baseline.count}** from **${d.baseline.devices}** devices`);
  L.push('');
  L.push(table(['GPU driver', 'devices'], d.baseline.topGpuDrivers.map((i) => [i.key, i.count])));

  L.push('## Ingest health');
  const ih = d.ingestHealth;
  L.push(`- Requests: ${ih.requests} · accepted: ${ih.accepted} · rejected: ${ih.rejected} · bytes in: ${ih.bytesIn}`);
  L.push(`- HTTP status: ${Object.entries(ih.httpStatus).map(([k, v]) => `${k}×${v}`).join(', ') || 'n/a'}`);
  L.push(`- Reject reasons: ${Object.entries(ih.rejectReasons).map(([k, v]) => `${k}×${v}`).join(', ') || 'none'}`);
  L.push('');

  L.push('## Suggested investigation prompts');
  L.push(d.suggestedPrompts.map((p, i) => `${i + 1}. ${p}`).join('\n'));
  L.push('');
  L.push(`_Data dictionary: \`${d.paths.dictionary}\` · raw events: \`${d.paths.rawEvents}\` · crash group state: \`${d.paths.crashGroupState}\`_`);
  L.push('');
  return L.join('\n');
}

const DICTIONARY_MD = `# LogicFlow telemetry bucket — data dictionary (schema v1)

Private bucket. Layout (all UTC dates):

| Path | Content | Retention |
| --- | --- | --- |
| v1/events/dt=YYYY-MM-DD/type=<crash|error|usage|scan|baseline>/part-*.ndjson.gz | One JSON event per line (envelope + server fields) | 90 days |
| v1/stats/dt=YYYY-MM-DD/stats-*.json | Ingest counters (accepted/rejected/reasons/http status) | 90 days |
| v1/rollups/daily/dt=YYYY-MM-DD.json | Aggregates, no installIds | 13 months |
| v1/crash_groups/state.json | Crash/error groups across time, no installIds | indefinite |
| v1/digests/YYYY-MM-DD.{md,json}, latest.{md,json} | Human/agent digest | indefinite |
| v1/triage/crash_groups.json | Optional manual overrides: { "<fingerprint>": {"status":"open|fixed|ignored","fixedIn":"1.2.3","note":"..."} } | indefinite |
| v1/erasures/<sha256(installId)>.json | Right-to-erasure tombstones | indefinite |

Event line = client envelope { schema, eventId, type, ts, installId, appVersion, osBuild, arch, tier, region, payload }
plus server-owned fields { receivedAt, dt, consent, fingerprint, ingestId }.
Schema: GET https://api.delgadologic.tech/v1/telemetry/schema (also schema/v1/event.schema.json in the repo).
fingerprint = sha256(exceptionType + top-3 normalized in-app frames) for crash; sha256(code|component|message-template|frames) for error.
BigQuery: dataset views events, crash_groups, baseline_devices, driver_index (see bigquery/ddl.sql).
`;

module.exports = { generateDigest, aggregateDay, cmpVersion, renderMarkdown, detectAnomalies, mergeStats, DIGEST_SCHEMA };
