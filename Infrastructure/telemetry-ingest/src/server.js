'use strict';

const { createApp } = require('./app');

const app = createApp();

app
  .listen()
  .then((addr) => {
    app.log('info', 'listening', { port: addr.port, storage: app.cfg.storage, keys: app.cfg.ingestKeys.length, schema: app.cfg.schemaVersion });
    if (app.cfg.ingestKeys.length === 0) app.log('warning', 'no_ingest_keys_configured_failing_closed', {});
  })
  .catch((e) => {
    app.log('error', 'listen_failed', { err: e.message });
    process.exit(1);
  });

let closing = false;
async function shutdown(signal) {
  if (closing) return;
  closing = true;
  app.log('info', 'shutdown', { signal });
  const t = setTimeout(() => process.exit(1), 9000);
  t.unref();
  try {
    await app.shutdown();
  } catch (e) {
    app.log('error', 'shutdown_failed', { err: e.message });
  }
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (e) => app.log('error', 'unhandled_rejection', { err: String(e && e.message ? e.message : e).slice(0, 200) }));
