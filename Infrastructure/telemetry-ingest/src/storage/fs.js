'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

/**
 * Local filesystem object store. Mirrors the minimal GCS surface the service
 * needs so the whole pipeline can be exercised end to end without any cloud.
 * Keys use forward slashes, exactly like GCS object names.
 */
class FsStorage {
  constructor(root) {
    this.root = path.resolve(root);
    this.kind = 'fs';
  }

  _p(key) {
    const resolved = path.resolve(this.root, ...String(key).split('/'));
    if (resolved !== this.root && !resolved.startsWith(this.root + path.sep)) {
      throw new Error('path traversal rejected');
    }
    return resolved;
  }

  async put(key, data) {
    const p = this._p(key);
    await fsp.mkdir(path.dirname(p), { recursive: true });
    const tmp = `${p}.tmp-${process.pid}-${Date.now()}`;
    await fsp.writeFile(tmp, data);
    await fsp.rename(tmp, p);
  }

  async get(key) {
    try {
      return await fsp.readFile(this._p(key));
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
  }

  async exists(key) {
    try {
      await fsp.access(this._p(key));
      return true;
    } catch {
      return false;
    }
  }

  async delete(key) {
    try {
      await fsp.unlink(this._p(key));
      return true;
    } catch (e) {
      if (e.code === 'ENOENT') return false;
      throw e;
    }
  }

  /** List object keys under a prefix (recursive, sorted). */
  async list(prefix) {
    const out = [];
    const base = this._p(prefix.replace(/\/+$/, '') || '.');
    const walk = async (dir) => {
      let entries;
      try {
        entries = await fsp.readdir(dir, { withFileTypes: true });
      } catch (e) {
        if (e.code === 'ENOENT') return;
        throw e;
      }
      for (const ent of entries) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) await walk(full);
        else if (!/\.tmp-\d+-\d+$/.test(ent.name)) {
          out.push(path.relative(this.root, full).split(path.sep).join('/'));
        }
      }
    };
    if (fs.existsSync(base) && fs.statSync(base).isFile()) return [path.relative(this.root, base).split(path.sep).join('/')];
    await walk(base);
    return out.filter((k) => k.startsWith(prefix.replace(/\/+$/, '')) || prefix === '').sort();
  }
}

module.exports = { FsStorage };
