import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const STORAGE_ROOT = path.resolve(__dirname, '../storage');
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
 * Cleans up / deletes a file if it exists. Used for error recovery.
 * @param {string} filePathOrStoredName 
 */
export async function cleanupFile(filePathOrStoredName) {
  try {
    let target = filePathOrStoredName;
    if (!path.isAbsolute(target)) {
      target = getSafeFilePath(target);
    }
    await fs.unlink(target);
  } catch {
    // Ignore ENOENT errors during cleanup
  }
}
