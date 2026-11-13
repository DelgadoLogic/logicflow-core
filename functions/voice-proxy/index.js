// ─────────────────────────────────────────────────────────────────────────────
// voice-proxy/index.js  —  LogicFlow Voice Agent Sovereign Server
// Soul document: SOUL.md (project root)
// Oracle prompt:  ORACLE_PROMPT.md (this directory)
//
// Deployed as a Google Cloud Function (gen2) on api.delgadologic.tech
//
// Endpoints:
//   POST /v1/voice/session/start  -> validates license, acquires lock, returns proxy WSS token
//   POST /v1/voice/session/end    -> records session usage for billing & releases lock
//   GET  /v1/voice/quota          -> validates license, returns remaining minutes
//
// Abuse Prevention:
//   - Gemini API key is in GCP Secret Manager (never in client binary)
//   - Per-license rate limit: 5 session starts per hour (Firestore counter)
//   - Per-edition monthly quota (Community: 0, Pro: 1800s, Enterprise: 12000s)
//   - Max concurrent sessions per license: 1 (Firestore transactional lock)
//   - Session tokens are short-lived JWTs (1h TTL, pinned HS256 or EdDSA, iss + aud verified)
//   - Machine fingerprint & seat activation check prevents license sharing across devices
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

let functionsFramework = null;
try {
  functionsFramework = require('@google-cloud/functions-framework');
} catch {
  // Optional in unit-test or standalone relay environments where functions-framework isn't preinstalled
}

let SecretManagerServiceClient = null;
try {
  ({ SecretManagerServiceClient } = require('@google-cloud/secret-manager'));
} catch {
  // Secret Manager falls back to environment variables in local/test runs
}

let FirestoreClass = null;
try {
  ({ Firestore: FirestoreClass } = require('@google-cloud/firestore'));
} catch {
  // Injectable in tests via createVoiceHandlers
}

const SALES_COLLECTION = 'artifacts/delgadologic/public/data/sales';
const LICENSES_COLLECTION = 'licenses';
const ACTIVATIONS_COLLECTION = 'license_activations';

const JWT_ISSUER = 'delgadologic.tech';
const JWT_AUDIENCE = 'logicflow-voice-relay';

// Quota in seconds per billing cycle
const EDITION_QUOTA = {
  free:       0,
  community:  0,
  pro:        1800,   // 30 minutes/month
  enterprise: 12000,  // ~3.3 hours/month
};

// Rate limit: max N session starts per hour per license
const RATE_LIMIT_PER_HOUR = 5;

// Max session duration the server will enforce (regardless of edition)
const MAX_SESSION_SECONDS = 600; // 10 minutes hard cap

const ALLOWED_CORS_ORIGINS = new Set([
  'https://delgadologic.tech',
  'https://www.delgadologic.tech',
  'https://api.delgadologic.tech',
  'https://docs.delgadologic.tech',
]);

// ── Oracle Identity (from SOUL.md) ───────────────────────────────────────────

const ORACLE_SYSTEM_PROMPT = `
You are Oracle — the voice of the DelgadoLogic AI, built by Delgado Creative Enterprises LLC d/b/a DelgadoLogic.

You are a trusted computer technician and knowledgeable friend. You understand Windows deeply. You are not a sales assistant, not an alarm system, and not a data broker. You help real people — including those who are not technical — understand and maintain their computers with honesty and clarity.

How you speak:
- Plain, direct language. No jargon unless the user introduces it first.
- Short, clear sentences. One idea at a time.
- Warm but not performatively cheerful. Never say "Great question!" or offer empty praise.
- Confident where you have data. Honest about uncertainty when you don't.
- Always frame findings as: "I found X, it means Y, here's what you can do."

Your values:
- Honesty: If the system is healthy, say so. Never manufacture urgency. Never describe a minor issue as "critical" or "dangerous."
- Respect: Treat every user as an intelligent adult. Explain the "why," not just the "what."
- Privacy: You analyze system metrics only — running processes, memory, disk health, temp file counts. You cannot read file content. This is enforced at the code level, not just policy. Say so if asked.
- Sovereignty: Running on the user's device is better than sending data to a server. Never push cloud features the user doesn't need.
- No manipulation: Never create false urgency. Never frame optional maintenance as mandatory. If the free tier solves the problem, say so.

Hard rules — never break these:
1. Do not exaggerate findings to seem more useful.
2. Do not read, reference, or describe user file content — ever.
3. Do not recommend actions that aren't needed.
4. Do not mention upgrades or Pro features unless the user directly asks.
5. Do not claim to be human when sincerely asked.
6. Do not execute irreversible operations without explicit user confirmation and a clear explanation of what will happen.
7. Do not transmit personal data.

When uncertain: say so. "I'm not certain whether this is a problem — here's what I can see."
When the user declines: accept it immediately. No follow-up pressure.

You have access to real-time system tools through LogicFlow. Use them. Share actual data, not generalities.
`.trim();

function buildGeminiSetupPayload(edition) {
  return {
    setup: {
      model: 'models/gemini-2.0-flash-live-001',
      generation_config: {
        response_modalities: ['AUDIO'],
        speech_config: {
          voice_config: {
            prebuilt_voice_config: { voice_name: 'Puck' },
          },
        },
        thinking_config: edition === 'enterprise'
          ? { thinking_budget: 1024 }
          : { thinking_budget: 0 },
      },
      system_instruction: {
        parts: [{ text: ORACLE_SYSTEM_PROMPT }],
      },
      input_audio_transcription: {},
      tools: [
        {
          function_declarations: [
            {
              name: 'junk_scan',
              description: 'Scans the system for junk files (temp files, browser caches, Windows update leftovers, recycle bin) and returns the total bytes recoverable without cleaning yet.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'junk_clean',
              description: 'Cleans junk files from the system. Only call this after confirming with the user. Returns bytes freed.',
              parameters: {
                type: 'object',
                properties: {
                  scope: {
                    type: 'string',
                    description: 'Cleaning scope',
                    enum: ['temp_only', 'browser_only', 'full'],
                  },
                },
                required: ['scope'],
              },
            },
            {
              name: 'system_overview',
              description: 'Returns a comprehensive snapshot of the system: CPU model, RAM total/available, disk health, OS version, uptime, and temperature if available.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'disk_health',
              description: 'Checks SMART health data for all physical drives. Returns health score, model, and any warning attributes.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'memory_status',
              description: 'Returns current RAM usage, total RAM, pagefile usage, and whether memory pressure is high.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'startup_analysis',
              description: 'Lists all startup programs with their performance impact score (1-10, higher = slower boot). Identifies which to disable.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'driver_scan',
              description: 'Scans all installed drivers and identifies outdated, missing, or problematic ones.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'network_optimize',
              description: 'Flushes DNS cache, resets Winsock catalog, and tunes TCP auto-tuning for maximum network speed.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'game_mode_toggle',
              description: 'Activates or deactivates High-Performance Turbo Mode to optimize CPU/GPU priority, power plan, and RAM.',
              parameters: {
                type: 'object',
                properties: {
                  enable: {
                    type: 'boolean',
                    description: 'True to activate Turbo Mode, False to deactivate.',
                  },
                  profile: {
                    type: 'string',
                    description: 'Optional Turbo Mode profile name when enabling.',
                    enum: ['Gaming', 'Streaming', 'Rendering', 'Benchmarking', 'Minimum', 'Work', 'Battery', 'Server', 'Smart'],
                  },
                },
                required: ['enable'],
              },
            },
            {
              name: 'cpu_speed',
              description: 'Returns the processor model, clock speed in GHz, core count, thread count, and current CPU utilization percentage.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'gpu_info',
              description: 'Returns dedicated GPU details including graphics adapter model, driver version, and video memory (VRAM).',
              parameters: { type: 'object', properties: {}, required: [] },
            },
            {
              name: 'logicflow_version',
              description: 'Returns the current LogicFlow version, edition (Community/Pro/Enterprise), and license status.',
              parameters: { type: 'object', properties: {}, required: [] },
            },
          ],
        },
      ],
    },
  };
}

// ── CORS Helper ──────────────────────────────────────────────────────────────

function applyCors(req, res) {
  const origin = req.headers?.origin;
  if (typeof origin === 'string' && origin.length > 0) {
    const isLocalDev = process.env.NODE_ENV !== 'production' && /^http:\/\/localhost(:\d+)?$/.test(origin);
    if (ALLOWED_CORS_ORIGINS.has(origin) || isLocalDev) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    } else if (req.method === 'OPTIONS') {
      res.status(403).end();
      return true;
    }
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '3600');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true;
  }
  return false;
}

// ── Pinned JWT Signing & Verification (HS256 symmetric OR EdDSA PEM) ─────────

function toBase64Url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function isEd25519Pem(keyMaterial) {
  if (typeof keyMaterial !== 'string' || !keyMaterial.includes('-----BEGIN')) return false;
  try {
    const normalized = keyMaterial.replace(/\\n/g, '\n');
    const keyObj = normalized.includes('PRIVATE KEY')
      ? crypto.createPrivateKey(normalized)
      : crypto.createPublicKey(normalized);
    return keyObj.asymmetricKeyType === 'ed25519';
  } catch {
    return false;
  }
}

function signVoiceSessionToken(claims, keyMaterial, ttlSeconds = 3600, nowMs = Date.now()) {
  if (typeof keyMaterial !== 'string' || keyMaterial.trim().length < 16) {
    throw new Error('VOICE_JWT_SECRET must be at least 16 characters');
  }
  const iat = Math.floor(nowMs / 1000);
  const exp = iat + ttlSeconds;
  const fullClaims = {
    ...claims,
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    iat,
    exp,
  };

  if (isEd25519Pem(keyMaterial)) {
    const privKey = crypto.createPrivateKey(keyMaterial.replace(/\\n/g, '\n'));
    const headerB64 = toBase64Url(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }));
    const payloadB64 = toBase64Url(JSON.stringify(fullClaims));
    const signingInput = `${headerB64}.${payloadB64}`;
    const sigB64 = toBase64Url(crypto.sign(null, Buffer.from(signingInput, 'utf8'), privKey));
    return `${signingInput}.${sigB64}`;
  }

  return jwt.sign(fullClaims, keyMaterial, {
    algorithm: 'HS256',
    noTimestamp: true,
  });
}

function verifyVoiceSessionToken(token, keyMaterial, nowMs = Date.now()) {
  if (typeof token !== 'string' || !token || typeof keyMaterial !== 'string' || keyMaterial.trim().length < 16) {
    throw new Error('Missing token or secret');
  }

  if (isEd25519Pem(keyMaterial)) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Malformed JWT');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (header.alg !== 'EdDSA') throw new Error('Unexpected JWT algorithm');

    const normalized = keyMaterial.replace(/\\n/g, '\n');
    const pubKey = normalized.includes('PRIVATE KEY')
      ? crypto.createPublicKey(crypto.createPrivateKey(normalized))
      : crypto.createPublicKey(normalized);

    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    const sig = Buffer.from(parts[2], 'base64url');
    if (!crypto.verify(null, signingInput, pubKey, sig)) {
      throw new Error('Invalid EdDSA signature');
    }

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const nowSec = Math.floor(nowMs / 1000);
    if (payload.iss !== JWT_ISSUER) throw new Error('Invalid issuer');
    if (payload.aud !== JWT_AUDIENCE) throw new Error('Invalid audience');
    if (typeof payload.exp !== 'number' || payload.exp <= nowSec) throw new Error('Token expired');
    if (!payload.license_key || !payload.session_id || !payload.edition) {
      throw new Error('Missing required voice claims');
    }
    return payload;
  }

  const payload = jwt.verify(token, keyMaterial, {
    algorithms: ['HS256'],
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    clockTimestamp: Math.floor(nowMs / 1000),
  });
  if (!payload.license_key || !payload.session_id || !payload.edition) {
    throw new Error('Missing required voice claims');
  }
  return payload;
}

// ── License & Sales Schema Normalization ─────────────────────────────────────

function normalizeEditionTier(raw) {
  const clean = String(raw || '').trim().toLowerCase().replace(/[-\s]/g, '_');
  if (['enterprise', 'logicflow_team_10', 'team_10', 'logicflow_enterprise', 'founder_pass', 'founderpass'].includes(clean)) {
    return 'enterprise';
  }
  if (['pro', 'logicflow_pro', 'family', 'sovereign_suite', 'sovereignsuite', 'aeon_pro'].includes(clean)) {
    return 'pro';
  }
  if (['community', 'logicflow_community'].includes(clean)) {
    return 'community';
  }
  if (['free', 'logicflow_free'].includes(clean)) {
    return 'free';
  }
  return null;
}

function isRevokedOrUnpaid(record) {
  if (!record || typeof record !== 'object') return true;
  if (record.revoked === true) return true;
  const status = String(record.status || '').trim().toLowerCase();
  if (['revoked', 'refunded', 'cancelled', 'suspended', 'pending', 'failed'].includes(status)) {
    return true;
  }
  if (!status) return true;
  return !['active', 'issued', 'completed', 'captured', 'paid'].includes(status);
}

function hashHwid(hwid) {
  return crypto.createHash('sha256').update(String(hwid || '')).digest('hex').slice(0, 24);
}

async function querySingleDoc(collectionRef, field, value) {
  if (!collectionRef || typeof collectionRef.where !== 'function') return null;
  const snap = await collectionRef.where(field, '==', value).limit(1).get();
  if (!snap || snap.empty || !Array.isArray(snap.docs) || snap.docs.length === 0) return null;
  return snap.docs[0];
}

// ── Factory for Production & Unit-Tested Handlers ────────────────────────────

let _defaultDb = null;
let _defaultSecrets = null;
let _cachedGeminiKey = null;
let _cachedJwtSecret = null;

function getDefaultDb() {
  if (!_defaultDb) {
    if (!FirestoreClass) throw new Error('@google-cloud/firestore is not available');
    _defaultDb = new FirestoreClass();
  }
  return _defaultDb;
}

function getDefaultSecretsClient() {
  if (!_defaultSecrets && SecretManagerServiceClient) {
    _defaultSecrets = new SecretManagerServiceClient();
  }
  return _defaultSecrets;
}

async function defaultGetGeminiKey() {
  if (process.env.GEMINI_LIVE_API_KEY) return process.env.GEMINI_LIVE_API_KEY.trim();
  if (_cachedGeminiKey) return _cachedGeminiKey;
  const client = getDefaultSecretsClient();
  if (!client) throw new Error('GEMINI_LIVE_API_KEY secret unavailable');
  const [version] = await client.accessSecretVersion({
    name: 'projects/manuel-portfolio-2026/secrets/GEMINI_LIVE_API_KEY/versions/latest',
  });
  _cachedGeminiKey = version.payload.data.toString('utf8').trim();
  return _cachedGeminiKey;
}

async function defaultGetJwtSecret() {
  if (process.env.VOICE_JWT_SECRET) return process.env.VOICE_JWT_SECRET.trim();
  if (_cachedJwtSecret) return _cachedJwtSecret;
  const client = getDefaultSecretsClient();
  if (!client) throw new Error('VOICE_JWT_SECRET secret unavailable');
  const [version] = await client.accessSecretVersion({
    name: 'projects/manuel-portfolio-2026/secrets/VOICE_JWT_SECRET/versions/latest',
  });
  _cachedJwtSecret = version.payload.data.toString('utf8').trim();
  return _cachedJwtSecret;
}

function createVoiceService(deps = {}) {
  const db = deps.db || getDefaultDb();
  const getJwtSecret = deps.getJwtSecret || defaultGetJwtSecret;
  const getGeminiKey = deps.getGeminiKey || defaultGetGeminiKey;
  const nowFn = deps.now || (() => new Date());
  const makeTimestamp = deps.makeTimestamp || (() => {
    if (FirestoreClass?.Timestamp?.fromDate) {
      return FirestoreClass.Timestamp.fromDate(nowFn());
    }
    return nowFn().toISOString();
  });

  /**
   * Validates `licenseKey` + `machineFingerprint` against BOTH `licenses` and
   * `artifacts/delgadologic/public/data/sales` + `license_activations` (matching Website/functions).
   */
  async function validateLicense(licenseKey, machineFingerprint) {
    const key = String(licenseKey || '').trim();
    const hwid = String(machineFingerprint || '').trim();
    if (!key || key.length > 128) {
      return { valid: false, reason: 'Invalid license key' };
    }

    const licensesCol = db.collection(LICENSES_COLLECTION);
    const salesCol = db.collection(SALES_COLLECTION);

    let licDoc = await licensesCol.doc(key).get();
    if (!licDoc.exists) {
      licDoc = (await querySingleDoc(licensesCol, 'licenseKey', key)) || licDoc;
    }

    let saleDoc = await salesCol.doc(key).get();
    if (!saleDoc.exists) {
      saleDoc =
        (await querySingleDoc(salesCol, 'licenseKey', key)) ||
        (await querySingleDoc(salesCol, 'captureId', key)) ||
        saleDoc;
    }

    if ((!licDoc || !licDoc.exists) && (!saleDoc || !saleDoc.exists)) {
      return { valid: false, reason: 'Unknown license key' };
    }

    const initialLicData = licDoc?.exists ? licDoc.data() : null;
    const initialSaleData = saleDoc?.exists ? saleDoc.data() : null;

    const canonicalOrderId = String(
      initialSaleData?.orderId ||
      initialLicData?.orderId ||
      (saleDoc?.exists ? saleDoc.id : '') ||
      (licDoc?.exists ? licDoc.id : key)
    ).trim();

    // Load canonical primary records so revocations/refunds and seat upgrades always apply
    const [primaryLicSnap, primarySaleSnap] = await Promise.all([
      canonicalOrderId && canonicalOrderId !== licDoc?.id
        ? licensesCol.doc(canonicalOrderId).get()
        : Promise.resolve(licDoc),
      canonicalOrderId && canonicalOrderId !== saleDoc?.id
        ? salesCol.doc(canonicalOrderId).get()
        : Promise.resolve(saleDoc),
    ]);

    const licData = primaryLicSnap?.exists ? primaryLicSnap.data() : initialLicData;
    const saleData = primarySaleSnap?.exists ? primarySaleSnap.data() : initialSaleData;

    if (licData && isRevokedOrUnpaid(licData)) {
      return { valid: false, reason: `License is ${licData.revoked ? 'revoked' : licData.status || 'inactive'}` };
    }
    if (saleData && isRevokedOrUnpaid(saleData)) {
      return { valid: false, reason: `Order is ${saleData.revoked ? 'revoked' : saleData.status || 'inactive'}` };
    }

    const rawTier =
      licData?.edition ||
      licData?.tier ||
      saleData?.edition ||
      saleData?.tier ||
      licData?.product ||
      saleData?.product;
    const edition = normalizeEditionTier(rawTier);
    if (!edition) {
      return { valid: false, reason: 'Unrecognized license tier' };
    }

    // Legacy single-machine lock field
    const legacyLock = licData?.machineLock || saleData?.machineLock;
    if (legacyLock && hwid && legacyLock !== hwid) {
      return { valid: false, reason: 'License locked to a different machine' };
    }

    // Multi-seat activation check against `license_activations` (matching Website/functions)
    if (hwid) {
      const deviceLimit = Math.max(
        1,
        Number(licData?.deviceLimit || saleData?.deviceLimit || saleData?.seats || (edition === 'enterprise' ? 10 : 3))
      );
      const activationsCol = db.collection(ACTIVATIONS_COLLECTION);
      if (typeof activationsCol.where === 'function') {
        const actSnap = await activationsCol.where('orderId', '==', canonicalOrderId).get();
        const activeDocs = (actSnap?.docs || []).filter((d) => d.data()?.revoked !== true);
        if (activeDocs.length > 0) {
          const expectedModernId = `${canonicalOrderId}_${hashHwid(hwid)}`;
          const expectedLegacyId = `${canonicalOrderId}_${hwid.substring(0, 12)}`;
          const matchingSeat = activeDocs.find(
            (d) =>
              d.id === expectedModernId ||
              d.id === expectedLegacyId ||
              d.data()?.hwid === hwid
          );
          if (!matchingSeat && activeDocs.length >= deviceLimit) {
            return { valid: false, reason: 'Device seat limit reached for this license' };
          }
        }
      }
    }

    return {
      valid: true,
      canonicalLicenseId: canonicalOrderId,
      edition,
      machineFingerprint: legacyLock || hwid,
    };
  }

  async function getRemainingQuota(canonicalLicenseId, edition) {
    const maxSeconds = EDITION_QUOTA[edition] ?? 0;
    if (maxSeconds === 0) return 0;

    const now = nowFn();
    const cycleId = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    const usageDoc = await db
      .collection('voice_usage')
      .doc(`${canonicalLicenseId}_${cycleId}`)
      .get();

    const usedSeconds = usageDoc.exists ? Number(usageDoc.data()?.seconds_used || 0) : 0;
    return Math.max(0, maxSeconds - usedSeconds);
  }

  async function checkRateLimit(canonicalLicenseId) {
    const hourBucket = Math.floor(nowFn().getTime() / 3600000);
    const ref = db.collection('voice_rate_limit').doc(`${canonicalLicenseId}_${hourBucket}`);

    return db.runTransaction(async (tx) => {
      const doc = await tx.get(ref);
      const count = doc.exists ? Number(doc.data()?.count || 0) : 0;
      if (count >= RATE_LIMIT_PER_HOUR) return false;
      tx.set(ref, { count: count + 1, updated_at_ms: nowFn().getTime() }, { merge: true });
      return true;
    });
  }

  /**
   * Acquires the per-license concurrent session lock (`voice_locks/{canonicalLicenseId}`).
   * Stale locks automatically expire after `ttlSeconds + 60` seconds if a relay crashes.
   */
  async function acquireSessionLock(canonicalLicenseId, sessionId, machineFingerprint, ttlSeconds) {
    const nowMs = nowFn().getTime();
    const lockRef = db.collection('voice_locks').doc(canonicalLicenseId);

    return db.runTransaction(async (tx) => {
      const snap = await tx.get(lockRef);
      if (snap.exists) {
        const lock = snap.data() || {};
        if (lock.active === true && Number(lock.expires_at_ms || 0) > nowMs && lock.session_id !== sessionId) {
          return false;
        }
      }
      tx.set(
        lockRef,
        {
          active: true,
          session_id: sessionId,
          license_key: canonicalLicenseId,
          machine_fingerprint: machineFingerprint,
          acquired_at_ms: nowMs,
          expires_at_ms: nowMs + (ttlSeconds + 60) * 1000,
        },
        { merge: true }
      );
      return true;
    });
  }

  /**
   * Releases the concurrent session lock and bills any unbilled session seconds idempotently
   * so calling both `voiceRelay.terminateSession` and `POST /v1/voice/session/end` never double-bills.
   */
  async function finalizeSessionUsage({
    canonicalLicenseId,
    sessionId,
    durationSeconds,
    functionCallsMade,
    endedBy = 'api',
  }) {
    const clampedSeconds = Math.max(0, Math.min(Math.floor(Number(durationSeconds) || 0), MAX_SESSION_SECONDS));
    const now = nowFn();
    const cycleId = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    const usageRef = db.collection('voice_usage').doc(`${canonicalLicenseId}_${cycleId}`);
    const lockRef = db.collection('voice_locks').doc(canonicalLicenseId);
    const sessionRef = sessionId ? db.collection('voice_sessions').doc(sessionId) : null;

    let deltaBilled = 0;

    await db.runTransaction(async (tx) => {
      const [usageSnap, lockSnap, sessionSnap] = await Promise.all([
        tx.get(usageRef),
        tx.get(lockRef),
        sessionRef ? tx.get(sessionRef) : Promise.resolve(null),
      ]);

      const alreadyBilled = sessionSnap?.exists ? Number(sessionSnap.data()?.billed_seconds || 0) : 0;
      const effectiveTotalForSession = Math.max(alreadyBilled, clampedSeconds);
      deltaBilled = Math.max(0, effectiveTotalForSession - alreadyBilled);

      if (deltaBilled > 0) {
        const currentCycleUsed = usageSnap.exists ? Number(usageSnap.data()?.seconds_used || 0) : 0;
        tx.set(
          usageRef,
          {
            seconds_used: currentCycleUsed + deltaBilled,
            license_key: canonicalLicenseId,
            cycle: cycleId,
          },
          { merge: true }
        );
      }

      if (lockSnap.exists) {
        const lockData = lockSnap.data() || {};
        if (!sessionId || !lockData.session_id || lockData.session_id === sessionId) {
          tx.set(
            lockRef,
            {
              active: false,
              released_at_ms: now.getTime(),
            },
            { merge: true }
          );
        }
      }

      if (sessionRef) {
        tx.set(
          sessionRef,
          {
            status: 'ended',
            ended_by: endedBy,
            ended_at: makeTimestamp(),
            duration_seconds: effectiveTotalForSession,
            billed_seconds: effectiveTotalForSession,
            ...(functionCallsMade !== undefined ? { function_calls_made: Number(functionCallsMade) || 0 } : {}),
          },
          { merge: true }
        );
      }
    });

    return { totalSessionSeconds: clampedSeconds, newlyBilledSeconds: deltaBilled };
  }

  // ── HTTP Handlers ──────────────────────────────────────────────────────────

  async function handleVoiceSessionStart(req, res) {
    if (applyCors(req, res)) return;
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { license_key, machine_fingerprint, client_version } = req.body || {};
    if (!license_key || !machine_fingerprint) {
      return res.status(400).json({ error: 'Missing license_key or machine_fingerprint' });
    }

    const licResult = await validateLicense(license_key, machine_fingerprint);
    if (!licResult.valid) {
      return res.status(403).json({ error: licResult.reason });
    }

    if (licResult.edition === 'community' || licResult.edition === 'free') {
      return res.status(403).json({
        error: 'Voice Agent is only available on Pro and Enterprise editions. Upgrade at delgadologic.tech/pricing',
      });
    }

    const canonicalId = licResult.canonicalLicenseId;

    const quotaRemaining = await getRemainingQuota(canonicalId, licResult.edition);
    if (quotaRemaining <= 0) {
      return res.status(429).json({
        error: `Monthly voice quota exhausted for ${licResult.edition} edition. Resets next billing cycle.`,
      });
    }

    const allowed = await checkRateLimit(canonicalId);
    if (!allowed) {
      return res.status(429).json({
        error: 'Too many session starts. Please wait before trying again.',
      });
    }

    const maxAllowedSeconds = Math.min(MAX_SESSION_SECONDS, quotaRemaining);
    const sessionId = crypto.randomUUID();

    const lockAcquired = await acquireSessionLock(
      canonicalId,
      sessionId,
      String(machine_fingerprint).trim(),
      maxAllowedSeconds
    );
    if (!lockAcquired) {
      return res.status(409).json({
        error: 'Another voice session is already active for this license.',
      });
    }

    let sessionToken;
    try {
      const jwtSecret = await getJwtSecret();
      sessionToken = signVoiceSessionToken(
        {
          sub: canonicalId,
          session_id: sessionId,
          license_key: canonicalId,
          raw_license_key: String(license_key).trim(),
          machine_fingerprint: String(machine_fingerprint).trim(),
          edition: licResult.edition,
        },
        jwtSecret,
        3600,
        nowFn().getTime()
      );
    } catch (err) {
      // Release lock if token signing fails so user isn't locked out
      await finalizeSessionUsage({
        canonicalLicenseId: canonicalId,
        sessionId,
        durationSeconds: 0,
        endedBy: 'start_abort',
      }).catch(() => {});
      console.error('[voice] Token signing failed:', err.message);
      return res.status(500).json({ error: 'Voice token generation failed' });
    }

    await db.collection('voice_sessions').doc(sessionId).set({
      session_id: sessionId,
      license_key: canonicalId,
      raw_license_key: String(license_key).trim(),
      machine_fingerprint: String(machine_fingerprint).trim(),
      edition: licResult.edition,
      client_version: String(client_version || '1.0.0').slice(0, 32),
      started_at: makeTimestamp(),
      status: 'started',
      billed_seconds: 0,
    });

    return res.status(200).json({
      session_token: sessionToken,
      session_id: sessionId,
      quota_remaining_seconds: quotaRemaining,
      edition: licResult.edition,
      max_session_seconds: maxAllowedSeconds,
      proxy_wss_url: 'wss://api.delgadologic.tech/v1/voice/proxy',
    });
  }

  async function handleVoiceSessionEnd(req, res) {
    if (applyCors(req, res)) return;
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { session_token, duration_seconds, function_calls_made } = req.body || {};
    if (!session_token) return res.status(400).json({ error: 'Missing session_token' });

    let payload;
    try {
      const jwtSecret = await getJwtSecret();
      payload = verifyVoiceSessionToken(session_token, jwtSecret, nowFn().getTime());
    } catch {
      return res.status(401).json({ error: 'Invalid or expired session token' });
    }

    const billing = await finalizeSessionUsage({
      canonicalLicenseId: payload.license_key,
      sessionId: payload.session_id,
      durationSeconds: duration_seconds,
      functionCallsMade: function_calls_made,
      endedBy: 'client_end',
    });

    return res.status(200).json({
      ok: true,
      seconds_billed: billing.newlyBilledSeconds,
      total_session_seconds: billing.totalSessionSeconds,
    });
  }

  async function handleVoiceQuota(req, res) {
    if (applyCors(req, res)) return;
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

    const licenseKey = String(req.query?.license_key || '').trim();
    const machineFingerprint = String(req.query?.machine_fingerprint || '').trim();
    if (!licenseKey) return res.status(400).json({ error: 'Missing license_key' });

    const licResult = await validateLicense(licenseKey, machineFingerprint);
    if (!licResult.valid) {
      return res.status(403).json({ error: licResult.reason });
    }

    const edition = licResult.edition;
    const remaining = await getRemainingQuota(licResult.canonicalLicenseId, edition);
    const max = EDITION_QUOTA[edition] ?? 0;

    return res.status(200).json({
      edition,
      total_seconds: max,
      used_seconds: Math.max(0, max - remaining),
      remaining_seconds: remaining,
      remaining_minutes: Math.floor(remaining / 60),
    });
  }

  return {
    validateLicense,
    getRemainingQuota,
    checkRateLimit,
    acquireSessionLock,
    finalizeSessionUsage,
    handleVoiceSessionStart,
    handleVoiceSessionEnd,
    handleVoiceQuota,
    getJwtSecret,
    getGeminiKey,
  };
}

let _defaultService = null;
function getDefaultService() {
  if (!_defaultService) {
    _defaultService = createVoiceService();
  }
  return _defaultService;
}

if (functionsFramework && typeof functionsFramework.http === 'function') {
  functionsFramework.http('voiceSessionStart', (req, res) => getDefaultService().handleVoiceSessionStart(req, res));
  functionsFramework.http('voiceSessionEnd', (req, res) => getDefaultService().handleVoiceSessionEnd(req, res));
  functionsFramework.http('voiceQuota', (req, res) => getDefaultService().handleVoiceQuota(req, res));
}

module.exports = {
  buildGeminiSetupPayload,
  ORACLE_SYSTEM_PROMPT,
  EDITION_QUOTA,
  RATE_LIMIT_PER_HOUR,
  MAX_SESSION_SECONDS,
  JWT_ISSUER,
  JWT_AUDIENCE,
  applyCors,
  signVoiceSessionToken,
  verifyVoiceSessionToken,
  normalizeEditionTier,
  createVoiceService,
  getDefaultService,
};
