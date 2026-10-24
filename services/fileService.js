import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { STORAGE_ROOT as CONFIGURED_STORAGE_ROOT } from './config.js';

export const STORAGE_ROOT = CONFIGURED_STORAGE_ROOT;
export const FILES_DIR = path.join(STORAGE_ROOT, 'files');
export const QUARANTINE_DIR = path.join(STORAGE_ROOT, 'quarantine');
export const TEMP_DIR = path.join(STORAGE_ROOT, 'temp');

/**
 * Initializes all required private storage directories on application startup.
 */
export async function initStorage() {
  await fs.mkdir(FILES_DIR, { recursive: true });
  await fs.mkdir(QUARANTINE_DIR, { recursive: true });
  await fs.mkdir(TEMP_DIR, { recursive: true });
}

/**
 * Generates an unguessable safe internal filename.
 * Does not use user-supplied names in the filesystem path.
 * @param {string} originalName 
 * @returns {string} Safe storage filename (e.g. uuid.dat)
 */
export function generateStoredName(originalName = '') {
  const safeId = crypto.randomUUID();
  const rawExt = path.extname(originalName).toLowerCase();
  // Strip non-alphanumeric characters from extension for safety
  const sanitizedExt = rawExt.replace(/[^a-z0-9.]/gi, '').slice(0, 10);
  return `${safeId}${sanitizedExt || '.dat'}`;
}

/**
 * Resolves and validates a file path within the files storage directory to prevent path traversal.
 * @param {string} storedName 
 * @returns {string} Absolute validated path
 */
export function getSafeFilePath(storedName) {
  // Disallow path traversal characters
  const sanitized = path.basename(storedName);
  const resolved = path.resolve(FILES_DIR, sanitized);
  if (!resolved.startsWith(FILES_DIR)) {
    throw new Error('Access denied: Invalid file path traversal attempt');
  }
  return resolved;
}

/**
 * Checks if a physical file exists on disk.
 * @param {string} storedName 
 * @returns {Promise<boolean>}
 */
export async function fileExists(storedName) {
  try {
    const filePath = getSafeFilePath(storedName);
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Moves a temporary file to the permanent files directory.
 * @param {string} sourceTempPath 
 * @param {string} targetStoredName 
 * @returns {Promise<string>} Target absolute path
 */
export async function moveToPermanentStorage(sourceTempPath, targetStoredName) {
  const destPath = getSafeFilePath(targetStoredName);
  await fs.rename(sourceTempPath, destPath);
  return destPath;
}

/**
 * Best-effort deletion used for error recovery paths where a failure to remove
 * a file must not mask the original error (for example discarding a temporary
 * upload after a rejected request).
 *
 * Prefer {@link deleteFileWithResult} whenever the caller needs to know whether
 * the deletion actually succeeded.
 *
 * @param {string} filePathOrStoredName
 */
export async function cleanupFile(filePathOrStoredName) {
  await deleteFileWithResult(filePathOrStoredName);
}

/**
 * Deletes a file and reports the precise outcome.
 *
 * Distinguishing a genuinely absent file from a failed deletion matters for the
 * cleanup worker: a record may only be marked 'deleted' when the ciphertext is
 * actually gone. A locked or permission-denied file (EBUSY / EPERM / EACCES,
 * common on Windows while a virus scanner or editor holds a handle) must keep
 * the record in a retryable state instead.
 *
 * @param {string} filePathOrStoredName - Absolute path, or a stored name inside FILES_DIR
 * @returns {Promise<{ outcome: 'deleted'|'missing'|'failed', code?: string, message?: string }>}
 */
export async function deleteFileWithResult(filePathOrStoredName) {
  let target = filePathOrStoredName;

  try {
    if (!path.isAbsolute(target)) {
      target = getSafeFilePath(target);
    }
  } catch (err) {
    // Path traversal attempt or unusable name: never treat this as a success.
    return { outcome: 'failed', code: 'EINVALIDPATH', message: err.message };
  }

  try {
    await fs.unlink(target);
    return { outcome: 'deleted' };
  } catch (err) {
    if (err.code === 'ENOENT') {
      // Already absent: the desired end state is satisfied.
      return { outcome: 'missing', code: err.code };
    }
    return { outcome: 'failed', code: err.code, message: err.message };
  }
}
