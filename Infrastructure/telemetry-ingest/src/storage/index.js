'use strict';

const { FsStorage } = require('./fs');
const { GcsStorage } = require('./gcs');

function createStorage(cfg) {
  if (cfg.storage === 'gcs') return new GcsStorage(cfg.bucket);
  return new FsStorage(cfg.dataDir);
}

module.exports = { createStorage, FsStorage, GcsStorage };
