import fs from 'node:fs/promises';
import path from 'node:path';
import { getAllFiles, updateFileRecord, removeFileRecord } from './metadataService.js';
import { getSafeFilePath, cleanupFile, TEMP_DIR } from './fileService.js';
import { FILE_STATUS } from './accessService.js';
import { hasActiveDownloads } from './operationCoordinator.js';

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

/**
 * Performs a single non-overlapping cleanup cycle.
 * Can be called manually in tests or automatically via timer.
 *
 * @returns {Promise<{ scanned: number, deleted: number, skippedBusy: number, errors: Array }>}
 */
export async function runCleanupCycle() {
  if (isCleanupRunning) {
    return { scanned: 0, deleted: 0, skippedBusy: 0, errors: [] };
  }

  isCleanupRunning = true;
  const results = { scanned: 0, deleted: 0, skippedBusy: 0, errors: [] };

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

        // Step 2: Delete permanent storage file
        if (record.storedName) {
          await cleanupFile(record.storedName);
        }

        // Step 3: Transition lifecycle to DELETED
        await updateFileRecord(record.id, {
          status: FILE_STATUS.DELETED,
          deletedAt: new Date().toISOString()
        });

        results.deleted++;
      } catch (fileErr) {
        // Record error for retry in next cycle
        results.errors.push({ id: record.id, error: fileErr.message });
      }
    }

    // Step 4: Clean up orphaned temporary files in TEMP_DIR older than 15 minutes
    try {
      const tempEntries = await fs.readdir(TEMP_DIR).catch(() => []);
      for (const tempName of tempEntries) {
        if (tempName === '.gitkeep') continue;
        const tempPath = path.join(TEMP_DIR, tempName);
        try {
          const stats = await fs.stat(tempPath);
          if (now - stats.mtimeMs > 15 * 60 * 1000) {
            await fs.unlink(tempPath).catch(() => {});
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
 * Starts the periodic background cleanup worker loop.
 * Also performs an immediate startup reconciliation.
 *
 * @param {number} [intervalMs]
 */
export async function startCleanupWorker(intervalMs = DEFAULT_CLEANUP_INTERVAL_MS) {
  if (cleanupTimer) return;

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
