// ─────────────────────────────────────────────────────────────────────────────
// voice-proxy/voiceRelay.js  —  LogicFlow Sovereign WebSocket Relay
// Soul document: SOUL.md (project root)
//
// This is the critical relay layer. It sits between the LogicFlow client and
// Google's Gemini Live endpoint. The client NEVER connects to Google directly.
//
// Enforcement layers:
//   1. Pinned JWT verification (HS256 or EdDSA, iss + aud + session_id verified)
//   2. Function allowlist — only declared functions can execute, nothing else
//   3. Irreversible action gate — destructive calls require prior confirmation
//   4. Path sanitizer — function args are validated to safe system paths only
//   5. Session state machine — actions out of order are rejected
//   6. Hard session cap — forcibly closed after MAX_SESSION_SECONDS & releases lock
//
// Deployment: Cloud Run (WebSocket-capable)
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

const http = require('node:http');
const WebSocket = require('ws');
const {
  buildGeminiSetupPayload,
  MAX_SESSION_SECONDS,
  verifyVoiceSessionToken,
  applyCors,
  getDefaultService,
} = require('./index');

const GEMINI_LIVE_URL =
  'wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent';

const SAFE_FUNCTIONS = new Set([
  'junk_scan',
  'junk_clean',
  'system_overview',
  'disk_health',
  'memory_status',
  'startup_analysis',
  'driver_scan',
  'network_optimize',
  'game_mode_toggle',
  'cpu_speed',
  'gpu_info',
  'logicflow_version',
]);

const REQUIRES_CONFIRMATION = new Set([
  'junk_clean',
]);

const SESSION_STATES = {
  ACTIVE: 'ACTIVE',
  AWAITING_CONFIRMATION: 'AWAITING_CONFIRMATION',
  CONFIRMATION_GRANTED: 'CONFIRMATION_GRANTED',
  TERMINATED: 'TERMINATED',
};

function isSafePath(pathStr) {
  if (!pathStr || typeof pathStr !== 'string') return true;
  const normalized = pathStr.replace(/\//g, '\\').toUpperCase();

  if (normalized.includes('..')) return false;

  const checkPath = normalized.endsWith('\\') ? normalized : `${normalized}\\`;
  const USER_CONTENT_DIRS = [
    '\\DOCUMENTS\\',
    '\\DESKTOP\\',
    '\\DOWNLOADS\\',
    '\\PICTURES\\',
    '\\VIDEOS\\',
    '\\MUSIC\\',
    '\\ONEDRIVE\\',
  ];
  for (const dir of USER_CONTENT_DIRS) {
    if (checkPath.includes(dir)) return false;
  }

  return true;
}

function validateFunctionArgs(args) {
  if (!args || typeof args !== 'object') return true;
  for (const val of Object.values(args)) {
    if (typeof val === 'string' && (val.includes('\\') || val.includes('/'))) {
      if (!isSafePath(val)) return false;
    }
    if (typeof val === 'object' && !validateFunctionArgs(val)) return false;
  }
  return true;
}

function createRelaySession({
  clientWs,
  licenseKey,
  sessionId,
  edition,
  geminiKey,
  finalizeSessionUsage,
  wsFactory = (url, opts) => new WebSocket(url, opts),
}) {
  const startTime = Date.now();
  let sessionState = SESSION_STATES.ACTIVE;
  let geminiWs = null;
  let hardCapTimer = null;

  const geminiUrl = `${GEMINI_LIVE_URL}?key=${encodeURIComponent(geminiKey)}`;
  geminiWs = wsFactory(geminiUrl, {
    headers: { 'Content-Type': 'application/json' },
  });

  hardCapTimer = setTimeout(() => {
    console.log(`[relay] Hard cap reached for license ${licenseKey}`);
    terminateSession('Session time limit reached');
  }, MAX_SESSION_SECONDS * 1000);
  if (typeof hardCapTimer.unref === 'function') {
    hardCapTimer.unref();
  }

  geminiWs.on('open', () => {
    console.log(`[relay] Gemini upstream open for ${licenseKey}`);
    const setupPayload = buildGeminiSetupPayload(edition);
    geminiWs.send(JSON.stringify(setupPayload));
  });

  geminiWs.on('message', (rawData) => {
    if (sessionState === SESSION_STATES.TERMINATED) return;

    let msg;
    try {
      msg = JSON.parse(rawData.toString());
    } catch {
      if (clientWs.readyState === WebSocket.OPEN) clientWs.send(rawData);
      return;
    }

    const toolCall = msg?.toolCall || msg?.serverContent?.toolCall;
    if (toolCall?.functionCalls?.length > 0) {
      for (const fc of toolCall.functionCalls) {
        const name = fc.name;
        const args = fc.args || {};

        if (!SAFE_FUNCTIONS.has(name)) {
          console.warn(`[safety] Blocked unknown function: "${name}" (license: ${licenseKey})`);
          sendBlockedResponse(fc.id, name, 'Function not permitted by safety policy');
          return;
        }

        if (!validateFunctionArgs(args)) {
          console.warn(`[safety] Blocked unsafe path in args for ${name} (license: ${licenseKey})`);
          sendBlockedResponse(fc.id, name, 'Argument contains restricted file path');
          return;
        }

        if (REQUIRES_CONFIRMATION.has(name)) {
          if (sessionState !== SESSION_STATES.CONFIRMATION_GRANTED) {
            console.warn(`[safety] Blocked ${name} — no confirmation in session state (license: ${licenseKey})`);
            sessionState = SESSION_STATES.AWAITING_CONFIRMATION;

            const blockMsg = JSON.stringify({
              toolResponse: {
                functionResponses: [
                  {
                    id: fc.id,
                    name,
                    response: {
                      content: {
                        error: 'CONFIRMATION_REQUIRED',
                        message:
                          'User must confirm this action before it can execute. Ask the user explicitly: "Should I go ahead and delete the temp files?" and wait for a clear yes.',
                      },
                    },
                  },
                ],
              },
            });
            if (geminiWs?.readyState === WebSocket.OPEN) {
              geminiWs.send(blockMsg);
            }
            return;
          }
          sessionState = SESSION_STATES.ACTIVE;
        }
      }
    }

    const userInputTranscript = msg?.serverContent?.inputTranscription?.text || '';
    if (/\b(yes|go ahead|do it|confirm|proceed|sure|ok|okay)\b/i.test(userInputTranscript)) {
      if (sessionState === SESSION_STATES.AWAITING_CONFIRMATION) {
        sessionState = SESSION_STATES.CONFIRMATION_GRANTED;
        console.log(`[relay] Confirmation granted for ${licenseKey}`);
      }
    }

    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(typeof msg === 'object' ? JSON.stringify(msg) : rawData);
    }
  });

  clientWs.on('message', (data) => {
    if (sessionState === SESSION_STATES.TERMINATED) return;
    try {
      const parsed = JSON.parse(data.toString());
      if (parsed && parsed.setup) {
        return;
      }
      if (parsed && parsed.userConfirmation === true && sessionState === SESSION_STATES.AWAITING_CONFIRMATION) {
        sessionState = SESSION_STATES.CONFIRMATION_GRANTED;
        return;
      }
    } catch {
      // Binary audio frame — forward below
    }
    if (geminiWs?.readyState === WebSocket.OPEN) {
      geminiWs.send(data);
    }
  });

  geminiWs.on('close', () => terminateSession('Gemini closed upstream'));
  geminiWs.on('error', (err) => {
    console.error(`[relay] Gemini error: ${err.message}`);
    terminateSession('Upstream error');
  });

  clientWs.on('close', () => terminateSession('Client disconnected'));
  clientWs.on('error', (err) => console.error(`[relay] Client error: ${err.message}`));

  function sendBlockedResponse(callId, name, reason) {
    if (geminiWs?.readyState === WebSocket.OPEN) {
      geminiWs.send(
        JSON.stringify({
          toolResponse: {
            functionResponses: [
              {
                id: callId,
                name,
                response: { content: { error: 'BLOCKED', message: reason } },
              },
            ],
          },
        })
      );
    }
  }

  function terminateSession(reason) {
    if (sessionState === SESSION_STATES.TERMINATED) return;
    sessionState = SESSION_STATES.TERMINATED;

    clearTimeout(hardCapTimer);

    const durationSeconds = Math.floor((Date.now() - startTime) / 1000);
    console.log(`[relay] Session ended (${reason}) — ${durationSeconds}s for ${licenseKey}`);

    if (typeof finalizeSessionUsage === 'function') {
      finalizeSessionUsage({
        canonicalLicenseId: licenseKey,
        sessionId,
        durationSeconds,
        endedBy: 'relay_close',
      }).catch((err) => console.error('[relay] Failed to finalize usage/lock:', err.message));
    }

    if (geminiWs?.readyState === WebSocket.OPEN) geminiWs.close();
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(JSON.stringify({ type: 'session_end', reason, duration_seconds: durationSeconds }));
      clientWs.close();
    }
  }
}

function createRelayServer(deps = {}) {
  const getService = deps.getService || getDefaultService;
  const nowFn = deps.now || (() => Date.now());

  const server = http.createServer((req, res) => {
    res.status = (code) => {
      res.statusCode = code;
      return res;
    };
    if (applyCors(req, res)) return;

    if (req.url === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'voice-relay' }));
      return;
    }
    res.writeHead(426, { 'Content-Type': 'text/plain' });
    res.end('WebSocket upgrade required');
  });

  const wss = new WebSocket.Server({ server });

  wss.on('connection', async (clientWs, req) => {
    const url = new URL(req.url || '/', 'http://localhost');
    const authHeader = String(req.headers?.authorization || '');
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const token = bearerToken || url.searchParams.get('token');

    if (!token) {
      clientWs.close(1008, 'Missing session token');
      return;
    }

    const svc = getService();
    let payload;
    try {
      const jwtSecret = await svc.getJwtSecret();
      payload = verifyVoiceSessionToken(token, jwtSecret, nowFn());
    } catch (err) {
      console.warn(`[relay] Invalid JWT: ${err.message}`);
      clientWs.close(1008, 'Invalid or expired session token');
      return;
    }

    const { license_key, session_id, edition } = payload;
    console.log(`[relay] Authenticated session ${session_id} — ${license_key} (${edition})`);

    let geminiKey;
    try {
      geminiKey = await svc.getGeminiKey();
    } catch (err) {
      console.error(`[relay] Failed to fetch Gemini key: ${err.message}`);
      clientWs.close(1011, 'Server configuration error');
      return;
    }

    createRelaySession({
      clientWs,
      licenseKey: license_key,
      sessionId: session_id,
      edition,
      geminiKey,
      finalizeSessionUsage: svc.finalizeSessionUsage,
      wsFactory: deps.wsFactory,
    });
  });

  return { server, wss };
}

const defaultRelay = createRelayServer();

if (require.main === module) {
  const PORT = process.env.PORT || 8080;
  defaultRelay.server.listen(PORT, () => {
    console.log(`[relay] Voice relay listening on :${PORT}`);
    console.log(
      `[relay] Safety: allowlist(${SAFE_FUNCTIONS.size} fns) + confirmation gate + path sanitizer + ${MAX_SESSION_SECONDS}s hard cap`
    );
  });
}

module.exports = {
  server: defaultRelay.server,
  wss: defaultRelay.wss,
  createRelayServer,
  createRelaySession,
  isSafePath,
  validateFunctionArgs,
  SAFE_FUNCTIONS,
  REQUIRES_CONFIRMATION,
  SESSION_STATES,
};
