import fs from 'node:fs/promises';
import path from 'node:path';
import { getAllFiles, updateFileRecord } from './metadataService.js';
import { deleteFileWithResult, FILES_DIR, TEMP_DIR } from './fileService.js';
import { FILE_STATUS } from './accessService.js';
import { hasActiveDownloads, isTempFileInUse } from './operationCoordinator.js';

/**
 * Background Automatic Expiry Cleanup Service
 *
 * Scans storage metadata periodically for expired records, coordinates with active downloads,
 * transitions lifecycle states safely (active -> deleting -> deleted), removes permanent
 * ciphertext files and temporary fragments, and recovers interrupted cleanups on restart.
 */

let cleanupTimer = null;
let isCleanupRunning = false;

export const DEFAULT_CLEANUP_INTERVAL_MS = parseInt(
  process.env.CLEANUP_INTERVAL_MS || '60000',
  10
);

/** Age after which an unreferenced temporary file is considered abandoned. */
export const TEMP_FILE_MAX_AGE_MS = parseInt(
  process.env.TEMP_FILE_MAX_AGE_MS || String(15 * 60 * 1000),
  10
);

/**
 * Performs a single non-overlapping cleanup cycle.
 * Can be called manually in tests or automatically via timer.
 *
 * @returns {Promise<{ scanned: number, deleted: number, skippedBusy: number, failed: number, tempRemoved: number, tempSkippedInUse: number, errors: Array }>}
 */
export async function runCleanupCycle() {
  if (isCleanupRunning) {
    return { scanned: 0, deleted: 0, skippedBusy: 0, failed: 0, tempRemoved: 0, tempSkippedInUse: 0, errors: [] };
  }

  isCleanupRunning = true;
  const results = {
    scanned: 0,
    deleted: 0,
    skippedBusy: 0,
    failed: 0,
    tempRemoved: 0,
    tempSkippedInUse: 0,
    errors: []
  };

  try {
    const allRecords = await getAllFiles();
    const now = Date.now();

    for (const record of allRecords) {
      results.scanned++;

      // Check for records that need cleanup:
      // 1. Records already in DELETING state (interrupted prior to completion or crash restart)
      // 2. ACTIVE records whose expiration timestamp has passed
      const isPastExpiry = record.expiresAt && new Date(record.expiresAt).getTime() <= now;
      const isPendingDeletion = record.status === FILE_STATUS.DELETING;

      if (!isPendingDeletion && (!isPastExpiry || record.status === FILE_STATUS.DELETED)) {
        continue;
      }

      // Check if an active download is currently streaming this file
      if (hasActiveDownloads(record.id)) {
        results.skippedBusy++;
        continue;
      }

      try {
        // Step 1: Mark file as DELETING so no new download can start
        if (record.status !== FILE_STATUS.DELETING) {
          await updateFileRecord(record.id, {
            status: FILE_STATUS.DELETING,
            deletingStartedAt: new Date().toISOString()
          });
        }

        // Re-check lease in case a download began concurrently right before status update
        if (hasActiveDownloads(record.id)) {
          results.skippedBusy++;
          continue;
        }

        // Step 2: Delete permanent storage file.
        // The lifecycle may only advance to DELETED when the ciphertext is
        // genuinely gone. A locked or permission-denied file must stay in the
        // retryable DELETING state so that a later cycle can finish the job,
        // rather than leaving metadata claiming a deletion that never happened.
        if (record.storedName) {
          const deletion = await deleteFileWithResult(record.storedName);

          if (deletion.outcome === 'failed') {
            await updateFileRecord(record.id, {
              status: FILE_STATUS.DELETING,
              lastCleanupError: {
                code: deletion.code || 'UNKNOWN',
                at: new Date().toISOString()
              }
            });

            results.failed++;
            results.errors.push({
              id: record.id,
              stage: 'unlink',
              code: deletion.code || 'UNKNOWN',
              error: `Physical deletion failed (${deletion.code || 'unknown error'}); record kept in '${FILE_STATUS.DELETING}' for retry`
            });
            console.warn(
              `[Cleanup Worker] Could not delete stored file for record ${record.id} ` +
              `(${deletion.code || 'unknown error'}). Will retry on the next cycle.`
            );
            continue;
          }
          // outcome === 'deleted' or 'missing': desired end state reached.
        }

        // Step 3: Transition lifecycle to DELETED, clearing any earlier error.
        await updateFileRecord(record.id, {
          status: FILE_STATUS.DELETED,
          deletedAt: new Date().toISOString(),
          lastCleanupError: null
        });

        results.deleted++;
      } catch (fileErr) {
        // Record error for retry in next cycle. The record keeps whatever
        // status it currently holds, so nothing is reported as deleted.
        results.failed++;
        results.errors.push({ id: record.id, stage: 'cycle', error: fileErr.message });
      }
    }

    // Step 4: Clean up stale temporary files in TEMP_DIR.
    // Files still registered as in use are skipped regardless of age, so a slow
    // upload or a long-running download is never pulled out from under itself.
    try {
      const tempEntries = await fs.readdir(TEMP_DIR).catch(() => []);
      for (const tempName of tempEntries) {
        if (tempName === '.gitkeep') continue;
        const tempPath = path.join(TEMP_DIR, tempName);

        if (isTempFileInUse(tempPath)) {
          results.tempSkippedInUse++;
          continue;
        }

        try {
          const stats = await fs.stat(tempPath);
          if (now - stats.mtimeMs > TEMP_FILE_MAX_AGE_MS) {
            const removal = await deleteFileWithResult(tempPath);
            if (removal.outcome === 'deleted') {
              results.tempRemoved++;
            } else if (removal.outcome === 'failed') {
              results.errors.push({
                stage: 'temp-unlink',
                code: removal.code || 'UNKNOWN',
                error: `Could not remove stale temporary file (${removal.code || 'unknown error'})`
              });
            }
          }
        } catch {}
      }
    } catch {}

  } catch (cycleErr) {
    results.errors.push({ general: cycleErr.message });
  } finally {
    isCleanupRunning = false;
  }

  return results;
}

/**
 * Read-only consistency audit of the metadata store against physical storage.
 *
 * Deliberately performs NO deletion. Deciding that a stored file is an orphan
 * is a guess: it could equally be a file whose metadata write was interrupted.
 * Reporting lets an operator inspect and decide, which is the safe default for
 * user data.
 *
 * @returns {Promise<{
 *   totalRecords: number,
 *   storedFiles: number,
 *   activeRecordsMissingFile: Array<{ id: string, storedName: string }>,
 *   filesWithoutRecord: string[],
 *   recordsStuckDeleting: Array<{ id: string, storedName: string }>,
 *   deletedRecordsWithFilePresent: Array<{ id: string, storedName: string }>
 * }>}
 */
export async function auditStorageConsistency() {
  const report = {
    totalRecords: 0,
    storedFiles: 0,
    activeRecordsMissingFile: [],
    filesWithoutRecord: [],
    recordsStuckDeleting: [],
    deletedRecordsWithFilePresent: []
  };

  const records = await getAllFiles();
  report.totalRecords = records.length;

  const entries = await fs.readdir(FILES_DIR).catch(() => []);
  const diskNames = new Set(entries.filter((name) => name !== '.gitkeep'));
  report.storedFiles = diskNames.size;

  const referencedNames = new Set();

  for (const record of records) {
    if (record.storedName) {
      referencedNames.add(record.storedName);
    }

    const present = record.storedName ? diskNames.has(record.storedName) : false;

    if (record.status === FILE_STATUS.ACTIVE && !present) {
      report.activeRecordsMissingFile.push({ id: record.id, storedName: record.storedName });
    }
    if (record.status === FILE_STATUS.DELETING) {
      report.recordsStuckDeleting.push({ id: record.id, storedName: record.storedName });
    }
    if (record.status === FILE_STATUS.DELETED && present) {
      report.deletedRecordsWithFilePresent.push({ id: record.id, storedName: record.storedName });
    }
  }

  for (const name of diskNames) {
    if (!referencedNames.has(name)) {
      report.filesWithoutRecord.push(name);
    }
  }

  return report;
}

/**
 * Starts the periodic background cleanup worker loop.
 * Also performs an immediate startup reconciliation.
 *
 * @param {number} [intervalMs]
 */
export async function startCleanupWorker(intervalMs = DEFAULT_CLEANUP_INTERVAL_MS) {
  if (cleanupTimer) return;

  // Startup consistency audit (reporting only, never deletes).
  try {
    const audit = await auditStorageConsistency();
    const anomalies =
      audit.activeRecordsMissingFile.length +
      audit.filesWithoutRecord.length +
      audit.deletedRecordsWithFilePresent.length;

    if (anomalies > 0) {
      console.warn(
        `[Cleanup Worker] Storage consistency audit found ${anomalies} anomaly(ies): ` +
        `${audit.activeRecordsMissingFile.length} active record(s) with no stored file, ` +
        `${audit.filesWithoutRecord.length} stored file(s) with no metadata record, ` +
        `${audit.deletedRecordsWithFilePresent.length} deleted record(s) whose file is still present. ` +
        'Nothing was removed automatically; inspect manually if unexpected.'
      );
    }
  } catch (err) {
    console.error('[Cleanup Worker] Consistency audit failed:', err.message);
  }

  // Immediate startup reconciliation of any interrupted or expired records
  try {
    await runCleanupCycle();
  } catch (err) {
    console.error('[Cleanup Worker] Initial reconciliation failed:', err.message);
  }

  // Start periodic timer (unreferenced so it does not block clean process exit)
  cleanupTimer = setInterval(() => {
    runCleanupCycle().catch((err) => {
      console.error('[Cleanup Worker] Error during background cycle:', err.message);
    });
  }, intervalMs);

  cleanupTimer.unref();
}

/**
 * Stops the periodic cleanup worker.
 */
export function stopCleanupWorker() {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}
