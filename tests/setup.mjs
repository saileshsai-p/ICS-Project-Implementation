/**
 * Test Environment Bootstrap
 *
 * Loaded with `node --test --import ./tests/setup.mjs` so it runs BEFORE any
 * application module is evaluated. That ordering is essential: the services
 * resolve their storage locations at import time, so the redirection must
 * already be in place. The real data/, storage/ and .env are never touched.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const RUN_ID = `${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
const TEST_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), `secushare-test-${RUN_ID}-`));

const TEST_DATA_DIR = path.join(TEST_ROOT, 'data');
const TEST_STORAGE_DIR = path.join(TEST_ROOT, 'storage');
const TEST_ENV_FILE = path.join(TEST_ROOT, '.env.test');

fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(TEST_STORAGE_DIR, 'files'), { recursive: true });
fs.mkdirSync(path.join(TEST_STORAGE_DIR, 'quarantine'), { recursive: true });
fs.mkdirSync(path.join(TEST_STORAGE_DIR, 'temp'), { recursive: true });

process.env.SECUSHARE_DATA_DIR = TEST_DATA_DIR;
process.env.SECUSHARE_STORAGE_DIR = TEST_STORAGE_DIR;
process.env.SECUSHARE_ENV_FILE = TEST_ENV_FILE;

// Overwritten even if the real key is exported in the shell, so a test run can
// never touch real ciphertext.
process.env.FILE_ENCRYPTION_MASTER_KEY = crypto.randomBytes(32).toString('hex');

// Suites invoke runCleanupCycle() explicitly; stop the worker firing on its own.
process.env.CLEANUP_INTERVAL_MS = process.env.CLEANUP_INTERVAL_MS || '3600000';

const { assertDisposableDataLocations, describeRuntimePaths } = await import('../services/config.js');
assertDisposableDataLocations('The automated test suite');

const paths = describeRuntimePaths();
if (paths.dataDir !== TEST_DATA_DIR || paths.storageRoot !== TEST_STORAGE_DIR) {
  throw new Error('Test isolation failed: configured paths do not match the temporary directories.');
}

/** Removes only this process's temp tree; guarded against deleting anything else. */
function cleanupTestRoot() {
  try {
    const resolved = path.resolve(TEST_ROOT);
    const insideTmp = resolved.toLowerCase().startsWith(path.resolve(os.tmpdir()).toLowerCase());
    const looksLikeOurs = path.basename(resolved).startsWith(`secushare-test-${RUN_ID}-`);

    if (insideTmp && looksLikeOurs) {
      fs.rmSync(resolved, { recursive: true, force: true });
    }
  } catch {
    // Leaving a temp directory behind is harmless; never fail the run over it.
  }
}

process.on('exit', cleanupTestRoot);

export { TEST_ROOT, TEST_DATA_DIR, TEST_STORAGE_DIR, TEST_ENV_FILE };
