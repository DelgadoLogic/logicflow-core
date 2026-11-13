// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow Guardian — Firebase Cloud Functions
// Smart Driver Updater Backend: Firestore Lookup + Gemini AI Analysis
// ─────────────────────────────────────────────────────────────────────────────

"use strict";

const crypto = require("node:crypto");
const { onRequest } = require("firebase-functions/v2/https");
const { onSchedule: onCron } = require("firebase-functions/v2/scheduler");
const admin = require("firebase-admin");
const { VertexAI } = require("@google-cloud/vertexai");

if (admin.apps.length === 0) {
  admin.initializeApp();
}
const db = admin.firestore();

// ─── Configuration ──────────────────────────────────────────────────────
const PROJECT_ID = process.env.GCLOUD_PROJECT || "logicflow-guardian";
const LOCATION = "us-central1";
const MAX_BATCH_OPS = 450; // Safely below Firestore's 500-operation hard limit
const MAX_LOOKUP_DEVICES = 250;
const MAX_AI_DEVICES = 150;
const MAX_AI_CRASH_DIGEST_BYTES = 32 * 1024;
const MAX_TELEMETRY_DRIVERS = 1000;
const INSTALL_ID_RE = /^[0-9a-f]{32}$/i;

// Pinned Sovereign License Public Keys (matches OmniLicense/LicenseEngine.cs)
const DEFAULT_LICENSE_ED25519_PUBKEY_SPKI_B64 =
  "MCowBQYDK2VwAyEABfoHnS014mgux9fNHwe0zzRPEqVoy0OOJ+5tVvfu3a4=";
const DEFAULT_LICENSE_RSA_PUBKEY_SPKI_B64 =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnKY2d5db/2/UsERcEKMH" +
  "FdMYMUj7msbr7tcbxxi8pZ/S/0ghaI5zgFjxvzx+a+y+H+L5tbQQQA5QG7B0F32J" +
  "1o/ynVgPc8E1S9PtwvvD3cUFvVn0cRTvR6pu3jup76uhy/t3gHit+bzxFcdMfmRV" +
  "hSuPXWO+qPzXm599++sgG8tr7eJwaFUVLNfri9G5G61ZWJR2zNZnTbQYryoKVhJO" +
  "UJfvPdyLmRiABzlqs/D3U0KmlwsnZ3tJWmZbOPE12k1WFVrISUGZ/EQje+z5QWd+" +
  "l8oO/lZ35YpbuLbFxvd3+4msMuKmXx03L8q/SsOy2E/JkefcpJdd09EgYM7IpDnR" +
  "LQIDAQAB";

const ALLOWED_LICENSE_TIERS = new Set([
  "pro",
  "community",
  "family",
  "enterprise",
  "sovereignsuite",
  "founderpass",
]);

// Fast in-memory sliding-window guard (backed up by Firestore hourly counters)
const memoryRateWindows = new Map();

function getClientIp(req) {
  const xff = req.headers?.["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim().length > 0) {
    return xff.split(",")[0].trim().substring(0, 64);
  }
  return String(req.ip || req.socket?.remoteAddress || "unknown").substring(0, 64);
}

function checkMemoryRateLimit(key, maxRequests, windowMs = 3600000, nowMs = Date.now()) {
  if (memoryRateWindows.size > 5000) {
    for (const [k, entry] of memoryRateWindows.entries()) {
      if (nowMs - entry.windowStart >= windowMs) {
        memoryRateWindows.delete(k);
      }
    }
  }
  const existing = memoryRateWindows.get(key);
  if (!existing || nowMs - existing.windowStart >= windowMs) {
    memoryRateWindows.set(key, { windowStart: nowMs, count: 1 });
    return true;
  }
  if (existing.count >= maxRequests) {
    return false;
  }
  existing.count += 1;
  return true;
}

async function enforceRateLimit(firestoreDb, scope, subject, ip, maxPerHour, nowMs = Date.now()) {
  const safeIp = crypto.createHash("sha256").update(String(ip || "unknown")).digest("hex").slice(0, 24);
  const safeSub = crypto.createHash("sha256").update(String(subject || safeIp)).digest("hex").slice(0, 24);

  if (!checkMemoryRateLimit(`${scope}:ip:${safeIp}`, Math.ceil(maxPerHour * 1.5), 3600000, nowMs)) {
    return false;
  }
  if (!checkMemoryRateLimit(`${scope}:sub:${safeSub}`, maxPerHour, 3600000, nowMs)) {
    return false;
  }

  if (!firestoreDb || typeof firestoreDb.runTransaction !== "function") {
    return true;
  }

  const hourBucket = Math.floor(nowMs / 3600000);
  const subRef = firestoreDb.collection("driver_rate_limits").doc(`${scope}_sub_${safeSub}_${hourBucket}`);
  const ipRef = firestoreDb.collection("driver_rate_limits").doc(`${scope}_ip_${safeIp}_${hourBucket}`);

  return firestoreDb.runTransaction(async (tx) => {
    const [subSnap, ipSnap] = await Promise.all([tx.get(subRef), tx.get(ipRef)]);
    const subCount = subSnap.exists ? Number(subSnap.data()?.count || 0) : 0;
    const ipCount = ipSnap.exists ? Number(ipSnap.data()?.count || 0) : 0;
    if (subCount >= maxPerHour || ipCount >= Math.ceil(maxPerHour * 1.5)) {
      return false;
    }
    const expiresAt = new Date((hourBucket + 2) * 3600000);
    tx.set(subRef, { count: subCount + 1, scope, expiresAt }, { merge: true });
    tx.set(ipRef, { count: ipCount + 1, scope, expiresAt }, { merge: true });
    return true;
  });
}

function loadPublicKeyFromSpkiOrPem(material, envOverride) {
  const source = (envOverride && envOverride.trim()) || material;
  if (source.includes("-----BEGIN")) {
    return crypto.createPublicKey(source.replace(/\\n/g, "\n"));
  }
  return crypto.createPublicKey({
    key: Buffer.from(source, "base64"),
    format: "der",
    type: "spki",
  });
}

function verifySignedLicenseHeader(rawHeader, now = new Date()) {
  if (typeof rawHeader !== "string" || rawHeader.trim().length === 0 || rawHeader.length > 8192) {
    return null;
  }
  try {
    const trimmed = rawHeader.trim();
    const jsonStr = trimmed.startsWith("{")
      ? trimmed
      : Buffer.from(trimmed, "base64").toString("utf8");
    const token = JSON.parse(jsonStr);
    const payload = token?.payload ?? token?.Payload;
    const signature = token?.signature ?? token?.Signature;
    const algRaw = String(token?.alg ?? token?.Alg ?? "").trim().toLowerCase();

    if (typeof payload !== "string" || !payload || typeof signature !== "string" || !signature) {
      return null;
    }

    const payloadBuf = Buffer.from(payload, "utf8");
    const sigBuf = Buffer.from(signature, "base64");
    let verified = false;

    if (algRaw === "ed25519" || (!algRaw && sigBuf.length === 64)) {
      if (sigBuf.length !== 64) return null;
      const edKey = loadPublicKeyFromSpkiOrPem(
        DEFAULT_LICENSE_ED25519_PUBKEY_SPKI_B64,
        process.env.LOGICFLOW_LICENSE_ED25519_PUBKEY
      );
      verified = crypto.verify(null, payloadBuf, edKey, sigBuf);
    } else if (
      algRaw === "rs256" ||
      algRaw === "rsa" ||
      algRaw === "rsa-2048" ||
      (!algRaw && sigBuf.length === 256)
    ) {
      if (sigBuf.length !== 256) return null;
      const rsaKey = loadPublicKeyFromSpkiOrPem(
        DEFAULT_LICENSE_RSA_PUBKEY_SPKI_B64,
        process.env.LOGICFLOW_LICENSE_RSA_PUBKEY
      );
      verified = crypto.verify("sha256", payloadBuf, rsaKey, sigBuf);
    }

    if (!verified) return null;

    const claims = JSON.parse(payload);
    if (!claims || typeof claims !== "object" || Array.isArray(claims)) return null;

    const tierRaw = String(claims.Tier ?? claims.tier ?? "").replace(/[-_\s]/g, "").toLowerCase();
    if (!ALLOWED_LICENSE_TIERS.has(tierRaw)) return null;

    const expRaw = claims.ExpiresAt ?? claims.expiresAt;
    const expMs = typeof expRaw === "string" ? Date.parse(expRaw) : NaN;
    if (!Number.isFinite(expMs) || expMs <= now.getTime()) return null;

    const subjectId = String(claims.OrderId || claims.orderId || claims.BoundHwid || "licensed").slice(0, 96);
    return {
      ok: true,
      method: "license_token",
      tier: tierRaw,
      subject: `lic:${subjectId}`,
    };
  } catch {
    return null;
  }
}

function getConfiguredHmacKeys() {
  const keys = [];
  const rawList = process.env.LF_INGEST_KEYS || process.env.DRIVER_API_HMAC_KEY || "";
  for (const part of rawList.split(",")) {
    const k = part.trim();
    if (k.length >= 16) keys.push(k);
  }
  if (keys.length === 0 && process.env.FUNCTIONS_EMULATOR === "true") {
    keys.push("logicflow-dev-ingest-key");
  }
  return keys;
}

function verifyPulseHmacHeader(req, { requireExtendedConsent = false } = {}) {
  const sigHeader = req.headers?.["x-lf-sig"];
  const installId = String(req.headers?.["x-lf-install-id"] || req.body?.installId || "").trim();
  const consent = String(req.headers?.["x-lf-consent"] || "").trim().toLowerCase();

  if (typeof sigHeader !== "string" || !INSTALL_ID_RE.test(installId)) {
    return null;
  }

  if (requireExtendedConsent) {
    if (consent !== "extended") {
      return { ok: false, status: 403, error: "Extended telemetry consent required" };
    }
  } else if (consent !== "standard" && consent !== "extended") {
    return { ok: false, status: 403, error: "Telemetry consent required" };
  }

  const keys = getConfiguredHmacKeys();
  if (keys.length === 0) return null;

  const hex = sigHeader.trim().replace(/^sha256=/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;

  const given = Buffer.from(hex, "hex");
  const wireBody = Buffer.isBuffer(req.rawBody)
    ? req.rawBody
    : Buffer.from(typeof req.rawBody === "string" ? req.rawBody : JSON.stringify(req.body || {}), "utf8");

  let matched = false;
  for (const key of keys) {
    const expected = crypto.createHmac("sha256", key).update(wireBody).digest();
    if (crypto.timingSafeEqual(expected, given)) {
      matched = true;
    }
  }

  if (!matched) return null;
  return {
    ok: true,
    method: "pulse_hmac",
    consent,
    installId: installId.toLowerCase(),
    subject: `inst:${installId.toLowerCase()}`,
  };
}

async function authenticateClientRequest(req, { authAdmin = admin.auth(), requireExtendedConsent = false, now = new Date() } = {}) {
  // 1. Signed LogicFlow License Token (Ed25519 or RSA-2048)
  const licHeader = req.headers?.["x-lf-license-token"];
  if (licHeader) {
    const licAuth = verifySignedLicenseHeader(licHeader, now);
    if (licAuth?.ok) {
      if (requireExtendedConsent) {
        const consent = String(req.headers?.["x-lf-consent"] || "").trim().toLowerCase();
        if (consent && consent !== "extended") {
          return { ok: false, status: 403, error: "Extended telemetry consent required" };
        }
      }
      return licAuth;
    }
  }

  // 2. Firebase Auth Bearer ID token
  const authHeader = String(req.headers?.authorization || "");
  if (authHeader.startsWith("Bearer ")) {
    const idToken = authHeader.slice(7).trim();
    if (idToken && authAdmin && typeof authAdmin.verifyIdToken === "function") {
      try {
        const decoded = await authAdmin.verifyIdToken(idToken);
        if (decoded?.uid) {
          return { ok: true, method: "firebase_auth", subject: `uid:${decoded.uid}` };
        }
      } catch {
        return { ok: false, status: 401, error: "Invalid Bearer token" };
      }
    }
  }

  // 3. Consent-bound Pulse HMAC signature
  const hmacResult = verifyPulseHmacHeader(req, { requireExtendedConsent });
  if (hmacResult) {
    return hmacResult;
  }

  return { ok: false, status: 401, error: "Authentication required" };
}

/**
 * Escapes all RegExp metacharacters except wildcard `*`, preventing regex injection / crashes.
 */
function compileHardwarePatternRegex(pattern) {
  const safe = String(pattern || "")
    .trim()
    .slice(0, 256)
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp(`^${safe}$`, "i");
}

/**
 * Commits an array of `{ ref, data, options }` Firestore writes in chunks of `<= MAX_BATCH_OPS` (450 < 500).
 */
async function commitChunkedWrites(firestoreDb, operations, chunkSize = MAX_BATCH_OPS) {
  if (!Array.isArray(operations) || operations.length === 0) return 0;
  const safeChunk = Math.max(1, Math.min(chunkSize, MAX_BATCH_OPS));
  let batchesCommitted = 0;

  for (let i = 0; i < operations.length; i += safeChunk) {
    const slice = operations.slice(i, i + safeChunk);
    const batch = firestoreDb.batch();
    for (const op of slice) {
      batch.set(op.ref, op.data, op.options || { merge: true });
    }
    await batch.commit();
    batchesCommitted += 1;
  }

  return batchesCommitted;
}

function sanitizeFieldSegment(raw, fallback = "unknown") {
  const cleaned = String(raw || fallback)
    .trim()
    .replace(/[./[\]*`~\\]/g, "_")
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .slice(0, 64);
  return cleaned || fallback;
}

function createHandlers(deps = {}) {
  const firestoreDb = deps.db || db;
  const authAdmin = deps.auth || admin.auth();
  const nowFn = deps.now || (() => new Date());
  const createGenerativeModel =
    deps.createGenerativeModel ||
    (() => {
      const vertexAi = new VertexAI({ project: PROJECT_ID, location: LOCATION });
      return vertexAi.getGenerativeModel({ model: "gemini-2.0-flash" });
    });
  const scrapers = deps.scrapers || {
    scrapeNvidiaLatest,
    scrapeAmdLatest,
    scrapeIntelLatest,
  };
  const serverTimestamp =
    deps.serverTimestamp || (() => admin.firestore.FieldValue.serverTimestamp());
  const increment =
    deps.increment || ((n) => admin.firestore.FieldValue.increment(n));

  async function handleDriversLookup(req, res) {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({ error: "POST required" });
      }

      const ip = getClientIp(req);
      if (!checkMemoryRateLimit(`lookup:ip:${ip}`, 120, 3600000, nowFn().getTime())) {
        return res.status(429).json({ error: "Too many lookup requests" });
      }

      const { drivers } = req.body || {};
      if (!Array.isArray(drivers) || drivers.length === 0) {
        return res.status(400).json({ error: "drivers array required" });
      }
      if (drivers.length > MAX_LOOKUP_DEVICES) {
        return res.status(400).json({ error: `drivers array exceeds maximum of ${MAX_LOOKUP_DEVICES}` });
      }

      const indexSnap = await firestoreDb.collection("driver_index").get();
      const index = [];
      indexSnap.forEach((doc) => index.push({ id: doc.id, ...doc.data() }));

      const results = [];

      for (const device of drivers) {
        if (!device || typeof device.HardwareId !== "string" || !device.HardwareId.trim()) continue;
        const hwid = device.HardwareId.trim().slice(0, 256).toUpperCase();

        for (const entry of index) {
          const patterns = Array.isArray(entry.hardware_id_patterns) ? entry.hardware_id_patterns : [];
          const matched = patterns.some((pattern) => compileHardwarePatternRegex(pattern).test(hwid));
          if (!matched) continue;

          const currentVersion = String(device.DriverVersion || "0.0.0.0").slice(0, 64);
          const indexVersion = String(entry.latest_version || "").slice(0, 64);

          if (indexVersion && compareVersions(indexVersion, currentVersion) > 0) {
            results.push({
              HardwareId: device.HardwareId,
              DeviceName: device.DeviceName || entry.device_name || "",
              CurrentVersion: currentVersion,
              LatestVersion: indexVersion,
              DownloadUrl: entry.download_url || "",
              SizeBytes: entry.size_bytes || 0,
              IsWhqlCertified: entry.whql_certified || false,
              Manufacturer: entry.manufacturer || "",
              ReleasedAt: entry.release_date || "",
              Source: "FirestoreIndex",
              InstallerFlags: entry.installer_flags || "",
              Category: entry.category || "Other",
            });
          }
          break;
        }
      }

      console.log(`driversLookup: ${drivers.length} devices -> ${results.length} updates`);
      return res.json(results);
    } catch (error) {
      console.error("driversLookup error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }

  async function handleDriversScanWithAi(req, res) {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({ error: "POST required" });
      }

      const now = nowFn();
      const authResult = await authenticateClientRequest(req, {
        authAdmin,
        requireExtendedConsent: false,
        now,
      });
      if (!authResult.ok) {
        return res.status(authResult.status || 401).json({ error: authResult.error || "Authentication required" });
      }

      const ip = getClientIp(req);
      const allowed = await enforceRateLimit(firestoreDb, "ai_scan", authResult.subject, ip, 10, now.getTime());
      if (!allowed) {
        return res.status(429).json({ error: "Hourly AI driver scan limit reached. Try again later." });
      }

      const { devices, crashDigest, systemInfo } = req.body || {};
      if (!Array.isArray(devices) || devices.length === 0 || !crashDigest) {
        return res.status(400).json({ error: "devices array and crashDigest required" });
      }
      if (devices.length > MAX_AI_DEVICES) {
        return res.status(400).json({ error: `devices array exceeds maximum of ${MAX_AI_DEVICES}` });
      }

      const digestStr = typeof crashDigest === "string" ? crashDigest : JSON.stringify(crashDigest);
      if (!digestStr || Buffer.byteLength(digestStr, "utf8") > MAX_AI_CRASH_DIGEST_BYTES) {
        return res.status(413).json({ error: "crashDigest exceeds maximum size of 32 KB" });
      }

      const safeDevices = devices.map((d) => ({
        DeviceName: String(d?.DeviceName || "").slice(0, 128),
        HardwareId: String(d?.HardwareId || "").slice(0, 128),
        DriverVersion: String(d?.DriverVersion || "").slice(0, 48),
        DeviceClass: String(d?.DeviceClass || "").slice(0, 48),
        DriverDate: String(d?.DriverDate || "").slice(0, 48),
      }));

      const safeSysInfo =
        systemInfo && typeof systemInfo === "object" && !Array.isArray(systemInfo)
          ? JSON.parse(JSON.stringify(systemInfo).slice(0, 2048))
          : {};

      const model = createGenerativeModel();
      const prompt = buildDriverAnalysisPrompt(safeDevices, digestStr, safeSysInfo);

      const result = await model.generateContent(prompt);
      const response = result.response;
      const text = response?.candidates?.[0]?.content?.parts?.[0]?.text || "[]";

      let recommendations = [];
      try {
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          if (Array.isArray(parsed)) recommendations = parsed.slice(0, 50);
        }
      } catch (parseError) {
        console.warn("Failed to parse AI response as JSON:", parseError.message);
      }

      const normalized = recommendations.map((rec) => ({
        DriverName: String(rec?.driverName || rec?.DriverName || "").slice(0, 128),
        HardwareId: String(rec?.hardwareId || rec?.HardwareId || "").slice(0, 128),
        Reason: String(rec?.reason || rec?.Reason || "").slice(0, 512),
        Confidence: Math.max(0, Math.min(1, parseFloat(rec?.confidence ?? rec?.Confidence ?? 0.5) || 0.5)),
        Severity: String(rec?.severity || rec?.Severity || "recommended").slice(0, 32),
        CrashSignatures: Array.isArray(rec?.crashSignatures || rec?.CrashSignatures)
          ? (rec.crashSignatures || rec.CrashSignatures).slice(0, 16).map((s) => String(s).slice(0, 64))
          : [],
        CrashCount: Math.max(0, parseInt(rec?.crashCount ?? rec?.CrashCount ?? 0, 10) || 0),
        SuggestedUpdate: rec?.suggestedUpdate || rec?.SuggestedUpdate || null,
      }));

      await firestoreDb.collection("driver_ai_analyses").add({
        timestamp: serverTimestamp(),
        subjectHash: crypto.createHash("sha256").update(authResult.subject).digest("hex").slice(0, 24),
        deviceCount: safeDevices.length,
        recommendationCount: normalized.length,
      });

      console.log(`driversScanWithAi: ${safeDevices.length} devices, ${normalized.length} AI recommendations`);
      return res.json(normalized);
    } catch (error) {
      console.error("driversScanWithAi error:", error);
      return res.status(500).json({ error: "AI analysis failed" });
    }
  }

  async function handleDriversScraperWeekly() {
    console.log("Weekly driver index scraper starting...");
    const updates = [];
    const nowIso = nowFn().toISOString();

    try {
      const nvidiaVersion = await scrapers.scrapeNvidiaLatest();
      if (nvidiaVersion) {
        updates.push({
          id: "nvidia_geforce_desktop",
          data: {
            latest_version: nvidiaVersion.version,
            download_url: nvidiaVersion.url,
            release_date: nowIso,
            updated_at: serverTimestamp(),
          },
        });
      }
    } catch (e) {
      console.warn("NVIDIA scrape failed:", e.message);
    }

    try {
      const amdVersion = await scrapers.scrapeAmdLatest();
      if (amdVersion) {
        updates.push({
          id: "amd_radeon_desktop",
          data: {
            latest_version: amdVersion.version,
            download_url: amdVersion.url,
            release_date: nowIso,
            updated_at: serverTimestamp(),
          },
        });
      }
    } catch (e) {
      console.warn("AMD scrape failed:", e.message);
    }

    try {
      const intelVersion = await scrapers.scrapeIntelLatest();
      if (intelVersion) {
        updates.push({
          id: "intel_graphics_desktop",
          data: {
            latest_version: intelVersion.version,
            download_url: intelVersion.url,
            release_date: nowIso,
            updated_at: serverTimestamp(),
          },
        });
      }
    } catch (e) {
      console.warn("Intel scrape failed:", e.message);
    }

    const operations = updates.map((u) => ({
      ref: firestoreDb.collection("driver_index").doc(u.id),
      data: u.data,
      options: { merge: true },
    }));
    await commitChunkedWrites(firestoreDb, operations, MAX_BATCH_OPS);

    console.log(`Weekly scraper complete: ${updates.length} drivers updated in index`);
    return updates.length;
  }

  async function handleDriversIngestTelemetry(req, res) {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({ error: "POST required" });
      }

      const now = nowFn();
      const authResult = await authenticateClientRequest(req, {
        authAdmin,
        requireExtendedConsent: true,
        now,
      });
      if (!authResult.ok) {
        return res.status(authResult.status || 401).json({ error: authResult.error || "Authentication required" });
      }

      const ip = getClientIp(req);
      const allowed = await enforceRateLimit(firestoreDb, "driver_telemetry", authResult.subject, ip, 12, now.getTime());
      if (!allowed) {
        return res.status(429).json({ error: "Telemetry rate limit exceeded" });
      }

      const { fingerprint, installId, eventType } = req.body || {};
      if (!fingerprint || !Array.isArray(fingerprint.KeyDrivers) || fingerprint.KeyDrivers.length === 0) {
        return res.status(400).json({ error: "fingerprint with non-empty KeyDrivers array required" });
      }
      if (fingerprint.KeyDrivers.length > MAX_TELEMETRY_DRIVERS) {
        return res.status(400).json({ error: `KeyDrivers exceeds maximum of ${MAX_TELEMETRY_DRIVERS}` });
      }
      if (installId !== undefined && installId !== null && !INSTALL_ID_RE.test(String(installId))) {
        return res.status(400).json({ error: "Invalid installId format" });
      }

      const ts = serverTimestamp();
      const isCrash = eventType === "crash";

      // Deduplicate repeated HardwareIds within a single request before chunking writes
      const operationsByDocKey = new Map();
      let validDriverCount = 0;

      for (const driver of fingerprint.KeyDrivers) {
        if (!driver || typeof driver.HwId !== "string" || !driver.HwId.trim()) continue;

        const hwid = driver.HwId.toUpperCase().trim().slice(0, 128);
        const docId = sanitizeFieldSegment(hwid.replace(/[\\/#]/g, "_"), "unknown_hwid").slice(0, 128);
        const telemetryRef = firestoreDb.collection("driver_telemetry").doc(docId);
        const safeVersion = sanitizeFieldSegment(driver.Version || "unknown", "unknown");

        validDriverCount += 1;
        operationsByDocKey.set(`drv:${docId}`, {
          ref: telemetryRef,
          data: {
            hardwareId: hwid,
            deviceClass: String(driver.Class || "").slice(0, 64),
            lastProvider: String(driver.Provider || "").slice(0, 128),
            lastSeen: ts,
            hitCount: increment(1),
            [`versions.${safeVersion}`]: increment(1),
            ...(isCrash && {
              crashCount: increment(1),
              lastCrashAt: ts,
            }),
          },
          options: { merge: true },
        });
      }

      if (typeof fingerprint.FirmwareVersion === "string" && fingerprint.FirmwareVersion.trim().length > 0) {
        const fwDocId = sanitizeFieldSegment(fingerprint.FirmwareManufacturer || "unknown", "unknown");
        const fwRef = firestoreDb.collection("firmware_telemetry").doc(fwDocId);
        operationsByDocKey.set(`fw:${fwDocId}`, {
          ref: fwRef,
          data: {
            manufacturer: String(fingerprint.FirmwareManufacturer || "").slice(0, 64),
            lastVersion: fingerprint.FirmwareVersion.trim().slice(0, 64),
            lastSeen: ts,
            hitCount: increment(1),
          },
          options: { merge: true },
        });
      }

      const operations = Array.from(operationsByDocKey.values());
      const batchesCommitted = await commitChunkedWrites(firestoreDb, operations, MAX_BATCH_OPS);

      checkAutoSuggestCandidates(firestoreDb, serverTimestamp).catch((e) =>
        console.warn("Auto-suggest check failed:", e.message)
      );

      console.log(
        `driversIngestTelemetry: ${validDriverCount} drivers (${batchesCommitted} batches), crash=${isCrash}`
      );

      return res.json({
        accepted: true,
        driversProcessed: validDriverCount,
        batchesCommitted,
      });
    } catch (error) {
      console.error("driversIngestTelemetry error:", error);
      return res.status(500).json({ error: "Telemetry ingestion failed" });
    }
  }

  return {
    handleDriversLookup,
    handleDriversScanWithAi,
    handleDriversScraperWeekly,
    handleDriversIngestTelemetry,
  };
}

const defaultHandlers = createHandlers();

exports.driversLookup = onRequest(
  { cors: true, region: LOCATION, memory: "256MiB" },
  (req, res) => defaultHandlers.handleDriversLookup(req, res)
);

exports.driversScanWithAi = onRequest(
  { cors: true, region: LOCATION, memory: "512MiB", timeoutSeconds: 60 },
  (req, res) => defaultHandlers.handleDriversScanWithAi(req, res)
);

exports.driversScraperWeekly = onCron(
  { schedule: "every sunday 02:00", region: LOCATION, memory: "512MiB", timeoutSeconds: 300 },
  () => defaultHandlers.handleDriversScraperWeekly()
);

exports.driversIngestTelemetry = onRequest(
  { cors: true, region: LOCATION, memory: "256MiB" },
  (req, res) => defaultHandlers.handleDriversIngestTelemetry(req, res)
);

/**
 * Checks driver_telemetry for hardware IDs seen 10+ times that
 * are NOT in the curated driver_index. Logs them as suggestions.
 */
async function checkAutoSuggestCandidates(
  firestoreDb = db,
  serverTimestamp = () => admin.firestore.FieldValue.serverTimestamp()
) {
  const telemetrySnap = await firestoreDb
    .collection("driver_telemetry")
    .where("hitCount", ">=", 10)
    .limit(50)
    .get();

  if (telemetrySnap.empty) return;

  const indexSnap = await firestoreDb.collection("driver_index").get();
  const indexedRegexes = [];
  indexSnap.forEach((doc) => {
    const patterns = doc.data().hardware_id_patterns || [];
    for (const p of patterns) {
      indexedRegexes.push(compileHardwarePatternRegex(p));
    }
  });

  const operations = [];
  for (const doc of telemetrySnap.docs) {
    const data = doc.data();
    const hwid = data.hardwareId || "";
    const alreadyIndexed = indexedRegexes.some((rx) => rx.test(hwid));

    if (!alreadyIndexed) {
      operations.push({
        ref: firestoreDb.collection("driver_index_suggestions").doc(doc.id),
        data: {
          hardwareId: hwid,
          deviceClass: data.deviceClass || "",
          lastProvider: data.lastProvider || "",
          hitCount: data.hitCount || 0,
          crashCount: data.crashCount || 0,
          versions: data.versions || {},
          suggestedAt: serverTimestamp(),
          status: "pending",
        },
        options: { merge: true },
      });
    }
  }

  await commitChunkedWrites(firestoreDb, operations, MAX_BATCH_OPS);
}

// ═══════════════════════════════════════════════════════════════════════════
//  HELPER: Build Gemini AI Prompt
// ═══════════════════════════════════════════════════════════════════════════

function buildDriverAnalysisPrompt(devices, crashDigest, systemInfo) {
  return `You are an expert Windows system diagnostician analyzing driver health.

TASK: Analyze the following system crash data and installed drivers. Identify which
drivers are likely causing system instability. Return ONLY a JSON array of recommendations.

SYSTEM INFO:
${JSON.stringify(systemInfo, null, 2)}

INSTALLED DRIVERS (${devices.length} total):
${JSON.stringify(
  devices.map((d) => ({
    name: d.DeviceName,
    hwid: d.HardwareId,
    version: d.DriverVersion,
    class: d.DeviceClass,
    date: d.DriverDate,
  })),
  null,
  2
)}

CRASH/ERROR DIGEST:
${typeof crashDigest === "string" ? crashDigest : JSON.stringify(crashDigest, null, 2)}

KNOWN CRASH-DRIVER CORRELATIONS:
- nvlddmkm.sys -> NVIDIA GPU driver
- atikmdag.sys / atikmpag.sys -> AMD GPU driver
- igdkmd64.sys -> Intel GPU driver
- RTKVHD64.sys -> Realtek Audio driver
- e1d65x64.sys -> Intel Ethernet driver
- Netwtw10.sys -> Intel WiFi driver
- storport.sys / stornvme.sys -> Storage controller driver
- NTFS.sys I/O errors -> Possible storage driver issue

RESPONSE FORMAT: Return ONLY a valid JSON array (no markdown, no explanation), where each
element has these fields:
- "driverName": string (device display name)
- "hardwareId": string (matching hardware ID from installed drivers, or empty)
- "reason": string (human-readable explanation of why this driver needs attention)
- "confidence": number (0.0 to 1.0, how confident the correlation is)
- "severity": string ("critical" if causing crashes, "recommended" if outdated, "optional" if minor)
- "crashSignatures": string[] (crash module names that triggered this recommendation)
- "crashCount": number (estimated crash count related to this driver)

If no driver issues are found, return an empty array: []

JSON ARRAY:`;
}

// ═══════════════════════════════════════════════════════════════════════════
//  HELPER: OEM Scraper Functions
// ═══════════════════════════════════════════════════════════════════════════

async function scrapeNvidiaLatest() {
  try {
    const url = "https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1";
    const response = await fetch(url);
    if (!response.ok) return null;

    const text = await response.text();
    const versionMatch = text.match(/<Version>([\d.]+)<\/Version>/);
    const urlMatch = text.match(/<DownloadURL>([^<]+)<\/DownloadURL>/);

    if (versionMatch) {
      return {
        version: versionMatch[1],
        url: urlMatch ? urlMatch[1] : "https://www.nvidia.com/Download/index.aspx",
      };
    }
  } catch (e) {
    console.warn("NVIDIA API scrape error:", e.message);
  }
  return null;
}

async function scrapeAmdLatest() {
  try {
    const url = "https://www.amd.com/en/support/downloads/drivers.html";
    const response = await fetch(url);
    if (!response.ok) return null;

    const text = await response.text();
    const versionMatch = text.match(/Adrenalin[\s\S]*?(\d+\.\d+\.\d+)/i);

    if (versionMatch) {
      return {
        version: versionMatch[1],
        url: "https://www.amd.com/en/support/downloads/drivers.html",
      };
    }
  } catch (e) {
    console.warn("AMD scrape error:", e.message);
  }
  return null;
}

async function scrapeIntelLatest() {
  try {
    const url = "https://downloadcenter.intel.com/product/80939/Graphics";
    const response = await fetch(url);
    if (!response.ok) return null;

    const text = await response.text();
    const versionMatch = text.match(/Intel.*?Graphics.*?Driver.*?(\d+\.\d+\.\d+\.\d+)/i);

    if (versionMatch) {
      return {
        version: versionMatch[1],
        url: "https://www.intel.com/content/www/us/en/download-center/home.html",
      };
    }
  } catch (e) {
    console.warn("Intel scrape error:", e.message);
  }
  return null;
}

function compareVersions(a, b) {
  const partsA = String(a || "").split(".").map((n) => Number(n) || 0);
  const partsB = String(b || "").split(".").map((n) => Number(n) || 0);
  const len = Math.max(partsA.length, partsB.length);

  for (let i = 0; i < len; i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;
    if (numA !== numB) return numA - numB;
  }
  return 0;
}

exports._internal = {
  createHandlers,
  authenticateClientRequest,
  verifySignedLicenseHeader,
  verifyPulseHmacHeader,
  commitChunkedWrites,
  compileHardwarePatternRegex,
  compareVersions,
  MAX_BATCH_OPS,
  memoryRateWindows,
};
