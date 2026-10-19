import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { getAllFiles, updateFileRecord } from './metadataService.js';
import { getSafeFilePath, fileExists, TEMP_DIR } from './fileService.js';
import { calculateFileSha256, verifySha256Digest } from './fileIntegrityService.js';
import {
  getMasterKey,
  encryptFileToStorage,
  decryptStorageToTemp,
  cleanupTempDecryptedFile
} from './encryptionService.js';

/**
 * Legacy Record Migration Service
 *
 * Upgrades baseline Version 1 unencrypted records to Version 2:
 * 1. Checks if record lacks encryption metadata.
 * 2. Verifies the legacy plaintext file exists on disk.
 * 3. Calculates the original SHA-256 integrity hash.
 * 4. Encrypts the file using AES-256-GCM under a fresh DEK and Master Key.
 * 5. Verifies the encrypted file decrypts properly and matches the original SHA-256.
 * 6. Safely replaces permanent storage.
 * 7. Atomically updates metadata only after full verification.
 * 8. Preserves all tokens, passwords, expiration, and download limits.
 */

/**
 * Migrates a single legacy record.
 * 
 * @param {Object} record - File metadata record
 * @param {Buffer} [masterKey] - Optional master key (defaults to getMasterKey())
 * @returns {Promise<{ migrated: boolean, record: Object, reason?: string }>}
 */
export async function migrateLegacyRecord(record, masterKey = getMasterKey()) {
  if (record.encryption && record.encryption.enabled) {
    return { migrated: false, record, reason: 'Already encrypted' };
  }

  const legacyPath = getSafeFilePath(record.storedName);
  const exists = await fileExists(record.storedName);

  if (!exists) {
    return {
      migrated: false,
      record,
      reason: `Physical legacy file ${record.storedName} not found on disk`
    };
  }

  // 1. Calculate original plaintext SHA-256
  const originalDigest = await calculateFileSha256(legacyPath);

  // 2. Encrypt into a staging file in temp
  const stagingStoredName = `migrated_${record.storedName}`;
  const stagingEncryptedPath = path.join(TEMP_DIR, stagingStoredName);

  const { encryptionMeta } = await encryptFileToStorage(
    legacyPath,
    // Note: encryptFileToStorage puts it in FILES_DIR, so let's use a unique name in FILES_DIR
    stagingStoredName,
    masterKey
  );

  // 3. Verify round-trip decryption
  let testDecryptedPath = null;
  try {
    testDecryptedPath = await decryptStorageToTemp(
      stagingStoredName,
      encryptionMeta,
      masterKey
    );

    const decryptedDigest = await calculateFileSha256(testDecryptedPath);
    if (!verifySha256Digest(decryptedDigest, originalDigest)) {
      throw new Error('Integrity check failed during migration test decryption');
    }
  } catch (verifyErr) {
    // Clean up staging files and abort
    await cleanupTempDecryptedFile(testDecryptedPath);
    try {
      await fs.unlink(getSafeFilePath(stagingStoredName));
    } catch {}
    throw new Error(`Migration verification failed for ${record.id}: ${verifyErr.message}`);
  } finally {
    await cleanupTempDecryptedFile(testDecryptedPath);
  }

  // 4. Safely replace the permanent file on disk
  const stagingPath = getSafeFilePath(stagingStoredName);
  await fs.rename(stagingPath, legacyPath);

  // 5. Update metadata with new encryption and integrity blocks
  const updates = {
    storageFormat: 'encrypted-v2',
    integrity: {
      algorithm: 'sha256',
      expectedDigest: originalDigest,
      version: 1
    },
    encryption: encryptionMeta,
    downloadPolicy: record.downloadPolicy || 'unlimited',
    downloadLimit: record.downloadLimit !== undefined ? record.downloadLimit : null,
    downloadCount: typeof record.downloadCount === 'number' ? record.downloadCount : 0
  };

  const updatedRecord = await updateFileRecord(record.id, updates);

  return {
    migrated: true,
    record: updatedRecord
  };
}

/**
 * Scans metadata and migrates all unencrypted legacy records.
 *
 * @param {Buffer} [masterKey]
 * @returns {Promise<{ total: number, migratedCount: number, skippedCount: number, errors: Array }>}
 */
export async function migrateAllLegacyRecords(masterKey = getMasterKey()) {
  const records = await getAllFiles();
  let migratedCount = 0;
  let skippedCount = 0;
  const errors = [];

  for (const record of records) {
    if (record.encryption && record.encryption.enabled) {
      skippedCount++;
      continue;
    }

    try {
      const result = await migrateLegacyRecord(record, masterKey);
      if (result.migrated) {
        migratedCount++;
      } else {
        skippedCount++;
      }
    } catch (err) {
      errors.push({ id: record.id, error: err.message });
    }
  }

  return {
    total: records.length,
    migratedCount,
    skippedCount,
    errors
  };
}
