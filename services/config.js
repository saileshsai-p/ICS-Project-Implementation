import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Central Runtime Path Configuration
 *
 * Every persistent location resolves through this module. Defaults point at the
 * real project directories, so `npm start` is unchanged; tests and benchmarks
 * override them via SECUSHARE_DATA_DIR / SECUSHARE_STORAGE_DIR /
 * SECUSHARE_ENV_FILE so they can never read or destroy real runtime data.
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PROJECT_ROOT = path.resolve(__dirname, '..');

export const DEFAULT_DATA_DIR = path.join(PROJECT_ROOT, 'data');
export const DEFAULT_STORAGE_DIR = path.join(PROJECT_ROOT, 'storage');
export const DEFAULT_ENV_FILE = path.join(PROJECT_ROOT, '.env');

function resolveOverride(rawValue, fallback) {
  if (typeof rawValue !== 'string' || !rawValue.trim()) {
    return fallback;
  }
  return path.resolve(rawValue.trim());
}

export const DATA_DIR = resolveOverride(process.env.SECUSHARE_DATA_DIR, DEFAULT_DATA_DIR);
export const STORAGE_ROOT = resolveOverride(process.env.SECUSHARE_STORAGE_DIR, DEFAULT_STORAGE_DIR);
export const ENV_FILE = resolveOverride(process.env.SECUSHARE_ENV_FILE, DEFAULT_ENV_FILE);

export const USING_DEFAULT_DATA_DIR = DATA_DIR === DEFAULT_DATA_DIR;
export const USING_DEFAULT_STORAGE_DIR = STORAGE_ROOT === DEFAULT_STORAGE_DIR;

/** Case-insensitive on Windows, matching filesystem semantics. */
export function isSameOrInside(parentPath, childPath) {
  const normalize = (p) => (process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p));
  const parent = normalize(parentPath);
  const child = normalize(childPath);

  if (parent === child) return true;

  const relative = path.relative(parent, child);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

/**
 * Safety guard for destructive callers (test setup, benchmarks).
 *
 * Refuses to continue unless both the data and storage directories point
 * outside the project tree, so a forgotten or mistyped override variable can
 * never clear real users, sessions, metadata or uploads.
 *
 * @throws {Error} when the configured locations are not disposable
 */
export function assertDisposableDataLocations(context = 'This operation') {
  const problems = [];

  if (USING_DEFAULT_DATA_DIR) {
    problems.push('SECUSHARE_DATA_DIR is not set, so the real data/ directory would be used');
  } else if (isSameOrInside(PROJECT_ROOT, DATA_DIR)) {
    problems.push(`SECUSHARE_DATA_DIR resolves inside the project tree (${DATA_DIR})`);
  }

  if (USING_DEFAULT_STORAGE_DIR) {
    problems.push('SECUSHARE_STORAGE_DIR is not set, so the real storage/ directory would be used');
  } else if (isSameOrInside(PROJECT_ROOT, STORAGE_ROOT)) {
    problems.push(`SECUSHARE_STORAGE_DIR resolves inside the project tree (${STORAGE_ROOT})`);
  }

  if (isSameOrInside(PROJECT_ROOT, ENV_FILE) && ENV_FILE === DEFAULT_ENV_FILE) {
    problems.push('SECUSHARE_ENV_FILE is not set, so the real .env file would be used');
  }

  if (problems.length > 0) {
    throw new Error(
      `${context} refuses to run against real application data.\n` +
      problems.map((p) => `  - ${p}`).join('\n') +
      '\nRedirect SECUSHARE_DATA_DIR, SECUSHARE_STORAGE_DIR and SECUSHARE_ENV_FILE to a ' +
      'disposable directory outside the project (see README section "Running tests safely").'
    );
  }
}

/** Active locations, for diagnostics. Paths only - never secrets. */
export function describeRuntimePaths() {
  return {
    projectRoot: PROJECT_ROOT,
    dataDir: DATA_DIR,
    storageRoot: STORAGE_ROOT,
    envFile: ENV_FILE,
    usingDefaultDataDir: USING_DEFAULT_DATA_DIR,
    usingDefaultStorageDir: USING_DEFAULT_STORAGE_DIR
  };
}
