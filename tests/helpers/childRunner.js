import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { PROJECT_ROOT } from '../../services/config.js';

/**
 * Helpers for exercising process-startup behaviour (master key resolution,
 * isolation guards), which cannot be tested in-process because the relevant
 * modules capture configuration at import time. Every helper works in a fresh
 * temp directory with disposable keys only.
 */

const activeRoots = new Set();

/**
 * Creates an isolated, disposable installation directory.
 *
 * @param {Object} [options]
 * @param {Array<Object>} [options.metadataRecords] - Records to seed metadata.json with
 * @param {string[]} [options.storedFiles] - File names to create inside storage/files
 * @param {string|null} [options.envFileContents] - Contents for the .env file (null = no file)
 * @returns {{ root: string, dataDir: string, storageDir: string, envFile: string }}
 */
export function createDisposableInstall({
  metadataRecords = null,
  storedFiles = [],
  envFileContents = null
} = {}) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), `secushare-child-${crypto.randomBytes(5).toString('hex')}-`)
  );
  activeRoots.add(root);

  const dataDir = path.join(root, 'data');
  const storageDir = path.join(root, 'storage');
  const envFile = path.join(root, '.env.child');

  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(storageDir, 'files'), { recursive: true });
  fs.mkdirSync(path.join(storageDir, 'temp'), { recursive: true });
  fs.mkdirSync(path.join(storageDir, 'quarantine'), { recursive: true });

  if (metadataRecords !== null) {
    fs.writeFileSync(
      path.join(dataDir, 'metadata.json'),
      JSON.stringify(metadataRecords, null, 2),
      'utf-8'
    );
  }

  for (const name of storedFiles) {
    fs.writeFileSync(path.join(storageDir, 'files', name), 'placeholder-ciphertext', 'utf-8');
  }

  if (envFileContents !== null) {
    fs.writeFileSync(envFile, envFileContents, 'utf-8');
  }

  return { root, dataDir, storageDir, envFile };
}

/** Guarded so only directories this helper created can be removed. */
export function destroyDisposableInstall(root) {
  if (!activeRoots.has(root)) return;
  try {
    const resolved = path.resolve(root);
    if (resolved.toLowerCase().startsWith(path.resolve(os.tmpdir()).toLowerCase())) {
      fs.rmSync(resolved, { recursive: true, force: true });
    }
  } catch {
    // Non-fatal.
  }
  activeRoots.delete(root);
}

/**
 * Runs an ES module snippet in a separate Node process. The snippet imports
 * services via the injected `SERVICES` file-URL prefix and prints one line
 * beginning with `RESULT:` followed by JSON.
 */
export function runInChild({ code, env = {} }) {
  const install = env.__install;
  const scriptPath = path.join(
    install ?? os.tmpdir(),
    `probe-${crypto.randomBytes(4).toString('hex')}.mjs`
  );

  const servicesUrl = pathToFileURL(path.join(PROJECT_ROOT, 'services')).href;
  const preamble = `const SERVICES = ${JSON.stringify(servicesUrl)};\n`;

  fs.writeFileSync(scriptPath, preamble + code, 'utf-8');

  // Start from the parent environment but strip anything that would leak the
  // real installation (including the real master key) into the child.
  const childEnv = { ...process.env };
  delete childEnv.FILE_ENCRYPTION_MASTER_KEY;
  delete childEnv.SECUSHARE_DATA_DIR;
  delete childEnv.SECUSHARE_STORAGE_DIR;
  delete childEnv.SECUSHARE_ENV_FILE;

  for (const [key, value] of Object.entries(env)) {
    if (key === '__install') continue;
    if (value === undefined) {
      delete childEnv[key];
    } else {
      childEnv[key] = value;
    }
  }

  const proc = spawnSync(process.execPath, [scriptPath], {
    env: childEnv,
    encoding: 'utf-8',
    cwd: PROJECT_ROOT,
    timeout: 30000
  });

  const stdout = proc.stdout || '';
  const resultLine = stdout.split(/\r?\n/).find((line) => line.startsWith('RESULT:'));

  let result = null;
  if (resultLine) {
    try {
      result = JSON.parse(resultLine.slice('RESULT:'.length));
    } catch {
      result = null;
    }
  }

  return { status: proc.status, stdout, stderr: proc.stderr || '', result };
}
