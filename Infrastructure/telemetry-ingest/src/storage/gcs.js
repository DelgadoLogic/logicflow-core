'use strict';

/**
 * GCS-backed object store (private bucket, uniform bucket-level access).
 * Same surface as FsStorage: put/get/exists/delete/list.
 * `@google-cloud/storage` is required lazily so FS-mode tests never load it.
 */
class GcsStorage {
  constructor(bucketName, { storageClient } = {}) {
    if (!bucketName) throw new Error('LF_BUCKET is required when LF_STORAGE=gcs');
    this.kind = 'gcs';
    this.bucketName = bucketName;
    if (storageClient) {
      this.bucket = storageClient.bucket(bucketName);
    } else {
      const { Storage } = require('@google-cloud/storage');
      this.bucket = new Storage().bucket(bucketName);
    }
  }

  async put(key, data, opts = {}) {
    const file = this.bucket.file(key);
    await file.save(data, {
      resumable: false,
      contentType: opts.contentType || contentTypeFor(key),
      metadata: { cacheControl: 'private, max-age=0, no-store' },
    });
  }

  async get(key) {
    try {
      const [buf] = await this.bucket.file(key).download();
      return buf;
    } catch (e) {
      if (e && (e.code === 404 || e.code === '404')) return null;
      throw e;
    }
  }

  async exists(key) {
    const [ok] = await this.bucket.file(key).exists();
    return ok;
  }

  async delete(key) {
    try {
      await this.bucket.file(key).delete();
      return true;
    } catch (e) {
      if (e && (e.code === 404 || e.code === '404')) return false;
      throw e;
    }
  }

  async list(prefix) {
    const [files] = await this.bucket.getFiles({ prefix, autoPaginate: true });
    return files.map((f) => f.name).sort();
  }
}

function contentTypeFor(key) {
  if (key.endsWith('.ndjson.gz')) return 'application/x-ndjson';
  if (key.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (key.endsWith('.json')) return 'application/json';
  return 'application/octet-stream';
}

module.exports = { GcsStorage, contentTypeFor };
