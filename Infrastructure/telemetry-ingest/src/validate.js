'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');

const SCHEMA_PATH = path.join(__dirname, '..', 'schema', 'v1', 'event.schema.json');
const TYPES = ['crash', 'error', 'usage', 'scan', 'baseline'];

/**
 * Build validators. `removeAdditional: true` strips unknown properties from
 * objects whose schema says additionalProperties:false - so client-supplied
 * server fields (receivedAt, consent, fingerprint, ...) never survive.
 */
function createValidator() {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  const ajv = new Ajv2020({ allErrors: false, removeAdditional: true, strict: true, useDefaults: false });
  addFormats(ajv);
  ajv.addSchema(schema);
  const envelope = ajv.compile({ $ref: `${schema.$id}` });
  const payloads = {};
  for (const t of TYPES) payloads[t] = ajv.compile({ $ref: `${schema.$id}#/$defs/payload.${t}` });

  /**
   * @returns {{ok:true, event:object} | {ok:false, reason:string, detail?:string}}
   * Mutates (strips) `event` in place.
   */
  function validateEvent(event) {
    if (event === null || typeof event !== 'object' || Array.isArray(event)) {
      return { ok: false, reason: 'schema_invalid', detail: 'event must be an object' };
    }
    if (!envelope(event)) {
      const err = envelope.errors && envelope.errors[0];
      return { ok: false, reason: 'schema_invalid', detail: err ? `${err.instancePath || '/'} ${err.message}` : 'invalid' };
    }
    const pv = payloads[event.type];
    if (!pv(event.payload)) {
      const err = pv.errors && pv.errors[0];
      return { ok: false, reason: 'payload_invalid', detail: err ? `payload${err.instancePath} ${err.message}` : 'invalid' };
    }
    return { ok: true, event };
  }

  return { validateEvent, schema };
}

module.exports = { createValidator, TYPES };
