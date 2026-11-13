"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const driverFns = require("../index.js");
const voiceProxy = require("../voice-proxy/index.js");
const voiceRelay = require("../voice-proxy/voiceRelay.js");

function createMockDb(seed = {}) {
  const store = new Map();
  for (const [colName, docs] of Object.entries(seed)) {
    const colMap = new Map();
    for (const [docId, data] of Object.entries(docs)) {
      colMap.set(docId, structuredClone(data));
    }
    store.set(colName, colMap);
  }

  const batchSizes = [];

  function getColMap(name) {
    if (!store.has(name)) store.set(name, new Map());
    return store.get(name);
  }

  function makeDocRef(colName, docId) {
    return {
      id: docId,
      _col: colName,
      async get() {
        const col = getColMap(colName);
        const exists = col.has(docId);
        const val = exists ? structuredClone(col.get(docId)) : undefined;
        return {
          id: docId,
          exists,
          data: () => val,
          ref: makeDocRef(colName, docId),
        };
      },
      async set(data, options) {
        const col = getColMap(colName);
        if (options?.merge && col.has(docId)) {
          col.set(docId, { ...col.get(docId), ...structuredClone(data) });
        } else {
          col.set(docId, structuredClone(data));
        }
      },
      async update(data) {
        const col = getColMap(colName);
        if (!col.has(docId)) throw new Error(`Missing doc ${colName}/${docId}`);
        col.set(docId, { ...col.get(docId), ...structuredClone(data) });
      },
    };
  }

  function makeQuery(colName, filters = [], maxLimit = Infinity) {
    return {
      where(field, op, value) {
        return makeQuery(colName, [...filters, { field, op, value }], maxLimit);
      },
      limit(n) {
        return makeQuery(colName, filters, n);
      },
      async get() {
        const col = getColMap(colName);
        const docs = [];
        for (const [id, raw] of col.entries()) {
          const ok = filters.every((f) => {
            const v = raw?.[f.field];
            if (f.op === "==") return v === f.value;
            if (f.op === ">=") return Number(v) >= Number(f.value);
            return false;
          });
          if (ok) {
            docs.push({
              id,
              exists: true,
              data: () => structuredClone(raw),
              ref: makeDocRef(colName, id),
            });
            if (docs.length >= maxLimit) break;
          }
        }
        return {
          empty: docs.length === 0,
          size: docs.length,
          docs,
          forEach: (cb) => docs.forEach(cb),
        };
      },
    };
  }

  return {
    batchSizes,
    store,
    collection(colName) {
      return {
        doc: (docId) => makeDocRef(colName, docId),
        async add(data) {
          const id = crypto.randomUUID();
          await makeDocRef(colName, id).set(data);
          return makeDocRef(colName, id);
        },
        where: (field, op, value) => makeQuery(colName, [{ field, op, value }]),
        limit: (n) => makeQuery(colName, [], n),
        get: () => makeQuery(colName, []).get(),
      };
    },
    batch() {
      const ops = [];
      return {
        set(ref, data, options) {
          ops.push({ ref, data, options });
          if (ops.length > 500) {
            throw new Error(`Firestore batch exceeded 500 ops (${ops.length})`);
          }
        },
        async commit() {
          if (ops.length > 500) {
            throw new Error(`Firestore batch exceeded 500 ops (${ops.length})`);
          }
          batchSizes.push(ops.length);
          for (const op of ops) {
            await op.ref.set(op.data, op.options);
          }
        },
      };
    },
    async runTransaction(fn) {
      const staged = [];
      const tx = {
        get: (ref) => ref.get(),
        set(ref, data, options) {
          staged.push(() => ref.set(data, options));
        },
      };
      const res = await fn(tx);
      for (const apply of staged) {
        await apply();
      }
      return res;
    },
  };
}

function createMockRes() {
  const headers = new Map();
  let statusCode = 200;
  let jsonBody = null;
  let ended = false;
  return {
    get statusCode() {
      return statusCode;
    },
    get jsonBody() {
      return jsonBody;
    },
    get ended() {
      return ended;
    },
    headers,
    setHeader(k, v) {
      headers.set(k.toLowerCase(), v);
    },
    status(code) {
      statusCode = code;
      return this;
    },
    json(obj) {
      jsonBody = obj;
      ended = true;
      return this;
    },
    end() {
      ended = true;
      return this;
    },
  };
}

test("driversScanWithAi rejects anonymous callers with 401 and accepts Ed25519 signed license tokens", async () => {
  driverFns._internal.memoryRateWindows.clear();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const prevPub = process.env.LOGICFLOW_LICENSE_ED25519_PUBKEY;
  process.env.LOGICFLOW_LICENSE_ED25519_PUBKEY = publicKey.export({ type: "spki", format: "pem" });

  try {
    const db = createMockDb();
    const handlers = driverFns._internal.createHandlers({
      db,
      auth: { verifyIdToken: async () => { throw new Error("bad token"); } },
      serverTimestamp: () => "2026-11-11T00:00:00Z",
      increment: (n) => n,
      createGenerativeModel: () => ({
        generateContent: async () => ({
          response: {
            candidates: [
              {
                content: {
                  parts: [
                    {
                      text: JSON.stringify([
                        {
                          driverName: "NVIDIA GeForce RTX 4090",
                          hardwareId: "PCI\\VEN_10DE&DEV_2684",
                          reason: "nvlddmkm TDR reset",
                          confidence: 0.94,
                          severity: "critical",
                          crashSignatures: ["nvlddmkm.sys"],
                          crashCount: 3,
                        },
                      ]),
                    },
                  ],
                },
              },
            ],
          },
        }),
      }),
    });

    // 1. Unauthenticated -> 401
    const unauthRes = createMockRes();
    await handlers.handleDriversScanWithAi(
      {
        method: "POST",
        headers: {},
        ip: "203.0.113.10",
        body: { devices: [{ HardwareId: "PCI\\VEN_10DE&DEV_2684" }], crashDigest: "nvlddmkm" },
      },
      unauthRes
    );
    assert.equal(unauthRes.statusCode, 401);

    // 2. Valid Ed25519 signed Pro license token -> 200
    const claimsJson = JSON.stringify({
      OrderId: "ORDER-PRO-1",
      BoundHwid: "HWID-1",
      Tier: "Pro",
      ExpiresAt: new Date(Date.now() + 86400000).toISOString(),
    });
    const sigB64 = crypto.sign(null, Buffer.from(claimsJson, "utf8"), privateKey).toString("base64");
    const headerVal = Buffer.from(
      JSON.stringify({ Payload: claimsJson, Signature: sigB64, Alg: "Ed25519" }),
      "utf8"
    ).toString("base64");

    const authRes = createMockRes();
    await handlers.handleDriversScanWithAi(
      {
        method: "POST",
        headers: { "x-lf-license-token": headerVal },
        ip: "203.0.113.10",
        body: {
          devices: [{ HardwareId: "PCI\\VEN_10DE&DEV_2684", DeviceName: "RTX 4090" }],
          crashDigest: "nvlddmkm timeout",
        },
      },
      authRes
    );
    assert.equal(authRes.statusCode, 200);
    assert.equal(authRes.jsonBody.length, 1);
    assert.equal(authRes.jsonBody[0].HardwareId, "PCI\\VEN_10DE&DEV_2684");
  } finally {
    if (prevPub === undefined) delete process.env.LOGICFLOW_LICENSE_ED25519_PUBKEY;
    else process.env.LOGICFLOW_LICENSE_ED25519_PUBKEY = prevPub;
  }
});

test("driversIngestTelemetry requires Extended consent + HMAC auth and chunks >500 driver writes <= 450 ops/batch", async () => {
  driverFns._internal.memoryRateWindows.clear();
  const prevKeys = process.env.LF_INGEST_KEYS;
  const hmacKey = "super-secret-ingest-key-2026-test";
  process.env.LF_INGEST_KEYS = hmacKey;

  try {
    const db = createMockDb();
    const handlers = driverFns._internal.createHandlers({
      db,
      auth: { verifyIdToken: async () => { throw new Error("nope"); } },
      serverTimestamp: () => "2026-11-11T00:00:00Z",
      increment: (n) => n,
    });

    const installId = "0123456789abcdef0123456789abcdef";
    const drivers = Array.from({ length: 620 }, (_, i) => ({
      HwId: `PCI\\VEN_8086&DEV_${String(i).padStart(4, "0")}`,
      Version: "31.0.101.5590",
      Class: "Display",
      Provider: "Intel",
    }));
    const bodyObj = {
      installId,
      eventType: "scan",
      fingerprint: {
        KeyDrivers: drivers,
        FirmwareManufacturer: "AMI",
        FirmwareVersion: "1.20",
      },
    };
    const rawBody = Buffer.from(JSON.stringify(bodyObj), "utf8");
    const sig = crypto.createHmac("sha256", hmacKey).update(rawBody).digest("hex");

    // 1. Standard consent rejected (403) because driver baseline requires Extended
    const stdRes = createMockRes();
    await handlers.handleDriversIngestTelemetry(
      {
        method: "POST",
        headers: {
          "x-lf-install-id": installId,
          "x-lf-consent": "standard",
          "x-lf-sig": sig,
        },
        rawBody,
        body: bodyObj,
        ip: "198.51.100.5",
      },
      stdRes
    );
    assert.equal(stdRes.statusCode, 403);

    // 2. Extended consent succeeds and splits 621 ops into 2 batches (450 + 171), each <= 450
    const extRes = createMockRes();
    await handlers.handleDriversIngestTelemetry(
      {
        method: "POST",
        headers: {
          "x-lf-install-id": installId,
          "x-lf-consent": "extended",
          "x-lf-sig": sig,
        },
        rawBody,
        body: bodyObj,
        ip: "198.51.100.5",
      },
      extRes
    );
    assert.equal(extRes.statusCode, 200);
    assert.equal(extRes.jsonBody.accepted, true);
    assert.equal(extRes.jsonBody.driversProcessed, 620);
    assert.equal(extRes.jsonBody.batchesCommitted, 2);
    assert.deepEqual(db.batchSizes, [450, 171]);
  } finally {
    if (prevKeys === undefined) delete process.env.LF_INGEST_KEYS;
    else process.env.LF_INGEST_KEYS = prevKeys;
  }
});

test("voice-proxy aligns with Website/functions sales & DL-PRO keys, enforces CORS, single-session lock, pinned JWT, and idempotent billing", async () => {
  const jwtSecret = "voice-jwt-test-secret-minimum-32-bytes-long!!";
  const orderId = "ORDER-PAYPAL-999";
  const captureId = "CAP-777";
  const dlKey = "DL-PRO-ABCD-EFGH-IJKL";
  const hwid1 = "DEVICE-FINGERPRINT-ONE";
  const hwidHash1 = crypto.createHash("sha256").update(hwid1).digest("hex").slice(0, 24);

  const db = createMockDb({
    "artifacts/delgadologic/public/data/sales": {
      [orderId]: {
        orderId,
        captureId,
        licenseKey: dlKey,
        status: "completed",
        tier: "Pro",
        product: "logicflow_pro",
        deviceLimit: 1,
        revoked: false,
      },
      [captureId]: {
        orderId,
        captureId,
        licenseKey: dlKey,
        status: "completed",
        tier: "Pro",
        product: "logicflow_pro",
      },
    },
    licenses: {
      [orderId]: {
        orderId,
        licenseKey: dlKey,
        status: "issued",
        tier: "Pro",
        deviceLimit: 1,
        revoked: false,
      },
    },
    license_activations: {
      [`${orderId}_${hwidHash1}`]: {
        orderId,
        hwid: hwid1,
        revoked: false,
      },
    },
  });

  const svc = voiceProxy.createVoiceService({
    db,
    getJwtSecret: async () => jwtSecret,
    getGeminiKey: async () => "fake-gemini-key",
    now: () => new Date("2026-11-11T12:00:00Z"),
  });

  // 1. CORS preflight OPTIONS returns 204 + Access-Control-Allow-Origin
  const optRes = createMockRes();
  await svc.handleVoiceSessionStart(
    { method: "OPTIONS", headers: { origin: "https://delgadologic.tech" } },
    optRes
  );
  assert.equal(optRes.statusCode, 204);
  assert.equal(optRes.headers.get("access-control-allow-origin"), "https://delgadologic.tech");

  // 2. Non-activated second HWID blocked when 1-seat limit is full
  const seatFullRes = createMockRes();
  await svc.handleVoiceSessionStart(
    {
      method: "POST",
      headers: {},
      body: { license_key: dlKey, machine_fingerprint: "UNREGISTERED-DEVICE-2" },
    },
    seatFullRes
  );
  assert.equal(seatFullRes.statusCode, 403);
  assert.match(seatFullRes.jsonBody.error, /seat limit/i);

  // 3. Valid DL-PRO key + activated HWID starts session and acquires lock
  const startRes = createMockRes();
  await svc.handleVoiceSessionStart(
    {
      method: "POST",
      headers: { origin: "https://delgadologic.tech" },
      body: { license_key: dlKey, machine_fingerprint: hwid1, client_version: "1.0.0" },
    },
    startRes
  );
  assert.equal(startRes.statusCode, 200);
  assert.equal(startRes.jsonBody.edition, "pro");
  assert.equal(startRes.jsonBody.quota_remaining_seconds, 1800);
  assert.ok(startRes.jsonBody.session_token);

  // 4. Concurrent session start using captureId (same canonical orderId!) blocked with 409
  const concurrentRes = createMockRes();
  await svc.handleVoiceSessionStart(
    {
      method: "POST",
      headers: {},
      body: { license_key: captureId, machine_fingerprint: hwid1 },
    },
    concurrentRes
  );
  assert.equal(concurrentRes.statusCode, 409);

  // 5. Relay terminate + client voiceSessionEnd do NOT double-bill, and release lock
  const relayBill = await svc.finalizeSessionUsage({
    canonicalLicenseId: orderId,
    sessionId: startRes.jsonBody.session_id,
    durationSeconds: 120,
    endedBy: "relay_close",
  });
  assert.equal(relayBill.newlyBilledSeconds, 120);

  const endRes = createMockRes();
  await svc.handleVoiceSessionEnd(
    {
      method: "POST",
      headers: {},
      body: {
        session_token: startRes.jsonBody.session_token,
        duration_seconds: 120,
        function_calls_made: 2,
      },
    },
    endRes
  );
  assert.equal(endRes.statusCode, 200);
  assert.equal(endRes.jsonBody.seconds_billed, 0);
  assert.equal(endRes.jsonBody.total_session_seconds, 120);

  // 6. Quota endpoint verifies license server-side (ignores spoofed edition query params)
  const quotaRes = createMockRes();
  await svc.handleVoiceQuota(
    {
      method: "GET",
      headers: {},
      query: { license_key: dlKey, edition: "enterprise" },
    },
    quotaRes
  );
  assert.equal(quotaRes.statusCode, 200);
  assert.equal(quotaRes.jsonBody.edition, "pro");
  assert.equal(quotaRes.jsonBody.total_seconds, 1800);
  assert.equal(quotaRes.jsonBody.remaining_seconds, 1680);

  // 7. Subsequent session can start now that lock was released
  const nextStartRes = createMockRes();
  await svc.handleVoiceSessionStart(
    {
      method: "POST",
      headers: {},
      body: { license_key: dlKey, machine_fingerprint: hwid1 },
    },
    nextStartRes
  );
  assert.equal(nextStartRes.statusCode, 200);

  // 8. Algorithm-confusion (`alg: none`) token is rejected
  const forgedToken = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${Buffer.from(
    JSON.stringify({
      iss: "delgadologic.tech",
      aud: "logicflow-voice-relay",
      license_key: orderId,
      session_id: "fake",
      edition: "pro",
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
  ).toString("base64url")}.`;
  assert.throws(() => voiceProxy.verifyVoiceSessionToken(forgedToken, jwtSecret));

  // 9. EdDSA PEM key signing & verification also works end-to-end
  const edPair = crypto.generateKeyPairSync("ed25519");
  const edPrivPem = edPair.privateKey.export({ type: "pkcs8", format: "pem" });
  const edPubPem = edPair.publicKey.export({ type: "spki", format: "pem" });
  const edJwt = voiceProxy.signVoiceSessionToken(
    { license_key: orderId, session_id: "sess-ed", edition: "pro" },
    edPrivPem
  );
  const edVerified = voiceProxy.verifyVoiceSessionToken(edJwt, edPubPem);
  assert.equal(edVerified.session_id, "sess-ed");

  // 10. voiceRelay path sanitizer blocks user content (with or without trailing slash) & traversal
  assert.equal(voiceRelay.isSafePath("C:\\Windows\\Temp\\foo.tmp"), true);
  assert.equal(voiceRelay.isSafePath("C:\\Users\\Alice\\Documents\\secret.docx"), false);
  assert.equal(voiceRelay.isSafePath("C:\\Users\\Alice\\Documents"), false);
  assert.equal(voiceRelay.isSafePath("C:\\Windows\\Temp\\..\\..\\Users\\Alice\\Desktop\\a.txt"), false);
});

test("voiceRelay intercepts top-level Gemini Live msg.toolCall, enforces allowlist/path/confirmation gates, and sends camelCase toolResponse", async () => {
  const { EventEmitter } = require("node:events");
  const WebSocket = require("ws");

  class FakeWs extends EventEmitter {
    constructor() {
      super();
      this.readyState = WebSocket.OPEN;
      this.sent = [];
      this.closed = false;
    }
    send(payload) {
      this.sent.push(typeof payload === "string" ? JSON.parse(payload) : payload);
    }
    close() {
      this.readyState = WebSocket.CLOSED;
      this.closed = true;
      this.emit("close");
    }
  }

  const clientWs = new FakeWs();
  let upstreamWs = null;

  voiceRelay.createRelaySession({
    clientWs,
    licenseKey: "ORDER-PRO-1",
    sessionId: "sess-relay-1",
    edition: "pro",
    geminiKey: "fake-key",
    finalizeSessionUsage: async () => ({ newlyBilledSeconds: 0 }),
    wsFactory: () => {
      upstreamWs = new FakeWs();
      return upstreamWs;
    },
  });

  // 1. Setup payload enables input_audio_transcription so voice confirmation works
  upstreamWs.emit("open");
  assert.equal(upstreamWs.sent.length, 1);
  assert.deepEqual(upstreamWs.sent[0].setup.input_audio_transcription, {});

  // 2. Top-level msg.toolCall with unknown function is blocked and NOT sent to clientWs
  upstreamWs.emit(
    "message",
    Buffer.from(
      JSON.stringify({
        toolCall: {
          functionCalls: [{ id: "fc-1", name: "shell_exec", args: { cmd: "whoami" } }],
        },
      })
    )
  );
  assert.equal(clientWs.sent.length, 0);
  assert.equal(upstreamWs.sent.length, 2);
  assert.equal(upstreamWs.sent[1].toolResponse.functionResponses[0].id, "fc-1");
  assert.equal(upstreamWs.sent[1].toolResponse.functionResponses[0].response.content.error, "BLOCKED");

  // 3. Top-level msg.toolCall with restricted user folder path is blocked
  upstreamWs.emit(
    "message",
    Buffer.from(
      JSON.stringify({
        toolCall: {
          functionCalls: [
            { id: "fc-2", name: "junk_scan", args: { target: "C:\\Users\\Alice\\Documents\\secret.docx" } },
          ],
        },
      })
    )
  );
  assert.equal(clientWs.sent.length, 0);
  assert.equal(upstreamWs.sent.length, 3);
  assert.equal(upstreamWs.sent[2].toolResponse.functionResponses[0].response.content.error, "BLOCKED");

  // 4. Top-level msg.toolCall for junk_clean requires confirmation first, then succeeds after yes transcript
  upstreamWs.emit(
    "message",
    Buffer.from(
      JSON.stringify({
        toolCall: {
          functionCalls: [{ id: "fc-3", name: "junk_clean", args: { scope: "temp_only" } }],
        },
      })
    )
  );
  assert.equal(clientWs.sent.length, 0);
  assert.equal(upstreamWs.sent.length, 4);
  assert.equal(
    upstreamWs.sent[3].toolResponse.functionResponses[0].response.content.error,
    "CONFIRMATION_REQUIRED"
  );

  // User confirms verbally via Gemini Live inputTranscription
  upstreamWs.emit(
    "message",
    Buffer.from(
      JSON.stringify({
        serverContent: { inputTranscription: { text: "Yes, go ahead." } },
      })
    )
  );
  assert.equal(clientWs.sent.length, 1);

  // Subsequent junk_clean toolCall is now allowed through to clientWs
  upstreamWs.emit(
    "message",
    Buffer.from(
      JSON.stringify({
        toolCall: {
          functionCalls: [{ id: "fc-4", name: "junk_clean", args: { scope: "temp_only" } }],
        },
      })
    )
  );
  assert.equal(clientWs.sent.length, 2);
  assert.equal(clientWs.sent[1].toolCall.functionCalls[0].id, "fc-4");

  clientWs.close();
});
