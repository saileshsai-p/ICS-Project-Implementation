import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const METADATA_FILE = path.join(DATA_DIR, 'metadata.json');
const METADATA_TMP_FILE = path.join(DATA_DIR, 'metadata.tmp.json');

// In-memory operation queue to serialize concurrent reads/writes
let writeQueue = Promise.resolve();

/**
 * Ensures data directory and metadata file exist.
 */
export async function initMetadataStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(METADATA_FILE);
  } catch {
    await fs.writeFile(METADATA_FILE, JSON.stringify([], null, 2), 'utf-8');
  }
}

/**
 * Reads all metadata records safely from disk.
 * @returns {Promise<Array>} Array of file records.
 */
async function readRecords() {
  await initMetadataStore();
  try {
    const data = await fs.readFile(METADATA_FILE, 'utf-8');
    if (!data.trim()) return [];
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    console.error('Error reading metadata.json:', err.message);
    throw new Error('Failed to read metadata storage');
  }
}

/**
 * Atomically writes records to disk via a temp file.
 * Handles Windows transient EPERM/EBUSY file locking gracefully.
 * @param {Array} records 
 */
async function writeRecords(records) {
  await initMetadataStore();
  const serialized = JSON.stringify(records, null, 2);
  await fs.writeFile(METADATA_TMP_FILE, serialized, 'utf-8');

  let retries = 5;
  while (retries > 0) {
    try {
      await fs.rename(METADATA_TMP_FILE, METADATA_FILE);
      return;
    } catch (err) {
      if ((err.code === 'EPERM' || err.code === 'EBUSY') && retries > 1) {
        retries--;
        await new Promise((r) => setTimeout(r, 25));
      } else {
        // Fallback write if rename is locked by Windows indexing or external handle
        await fs.writeFile(METADATA_FILE, serialized, 'utf-8');
        await fs.unlink(METADATA_TMP_FILE).catch(() => {});
        return;
      }
    }
  }
}

/**
 * Queues an operation to prevent concurrent write collisions.
 * @param {Function} task 
 */
function queueTask(task) {
  const result = writeQueue.then(task);
  writeQueue = result.catch(() => {});
  return result;
}

/**
 * Ensures backward-compatible defaults for existing records that lack V2 fields.
 * @param {Object|null} record
 * @returns {Object|null}
 */
export function normalizeRecord(record) {
  if (!record) return null;
  return {
    ...record,
    downloadPolicy: record.downloadPolicy || 'unlimited',
    downloadLimit: record.downloadLimit !== undefined ? record.downloadLimit : null,
    downloadCount: typeof record.downloadCount === 'number' ? record.downloadCount : 0,
    status: record.status || 'active',
    scanStatus: record.scanStatus || 'not_scanned',
    authorizedRecipients: Array.isArray(record.authorizedRecipients) ? record.authorizedRecipients : []
  };
}

/**
 * Retrieves all stored metadata records.
 */
export async function getAllFiles() {
  return queueTask(async () => {
    const records = await readRecords();
    return records.map(normalizeRecord);
  });
}

/**
 * Finds a record by its public share token.
 * @param {string} token 
 */
export async function getFileByToken(token) {
  return queueTask(async () => {
    const records = await readRecords();
    const found = records.find((item) => item.shareToken === token);
    return found ? normalizeRecord(found) : null;
  });
}

/**
 * Finds a record by its internal file ID.
 * @param {string} id 
 */
export async function getFileById(id) {
  return queueTask(async () => {
    const records = await readRecords();
    const found = records.find((item) => item.id === id);
    return found ? normalizeRecord(found) : null;
  });
}

/**
 * Appends a new file record.
 * @param {Object} record 
 */
export async function addFileRecord(record) {
  return queueTask(async () => {
    const records = await readRecords();
    records.push(record);
    await writeRecords(records);
    return record;
  });
}

/**
 * Updates an existing file record by ID.
 * @param {string} id 
 * @param {Object} updates 
 */
export async function updateFileRecord(id, updates) {
  return queueTask(async () => {
    const records = await readRecords();
    const index = records.findIndex((item) => item.id === id);
    if (index === -1) {
      throw new Error(`Record with id ${id} not found`);
    }
    records[index] = { ...records[index], ...updates };
    await writeRecords(records);
    return records[index];
  });
}

/**
 * Deletes a file record by ID.
 * @param {string} id 
 */
export async function removeFileRecord(id) {
  return queueTask(async () => {
    const records = await readRecords();
    const filtered = records.filter((item) => item.id !== id);
    await writeRecords(filtered);
    return true;
  });
}

/**
 * Atomically checks and consumes a single download allowance for a file.
 * Guaranteed atomic within a single Node.js process via the serialized queue.
 *
 * @param {string} idOrToken - File ID or Share Token
 * @returns {Promise<{ success: boolean, reason?: string, status?: number, record?: Object }>}
 */
export async function consumeDownloadAllowance(idOrToken) {
  return queueTask(async () => {
    const records = await readRecords();
    const index = records.findIndex(
      (item) => item.id === idOrToken || item.shareToken === idOrToken
    );

    if (index === -1) {
      return {
        success: false,
        reason: 'File not found.',
        status: 404
      };
    }

    const record = records[index];
    const currentCount = typeof record.downloadCount === 'number' ? record.downloadCount : 0;
    const limit = record.downloadLimit;

    // Check if limit is finite and already reached
    if (limit !== null && limit !== undefined && currentCount >= limit) {
      return {
        success: false,
        reason: 'This download link has reached its maximum download limit.',
        status: 410,
        downloadCount: currentCount,
        downloadLimit: limit
      };
    }

    // Atomically increment and persist
    record.downloadCount = currentCount + 1;
    await writeRecords(records);

    return {
      success: true,
      downloadCount: record.downloadCount,
      downloadLimit: limit,
      record: normalizeRecord(record)
    };
  });
}
