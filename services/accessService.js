import { fileExists, getSafeFilePath } from './fileService.js';
import { verifyPassword } from './passwordService.js';
import { SCAN_STATUS } from './malwareScanner.js';

export const FILE_STATUS = {
  ACTIVE: 'active',
  DELETING: 'deleting',
  DELETED: 'deleted',
  PENDING_SCAN: 'pending_scan',
  BLOCKED: 'blocked',
  UNAVAILABLE: 'unavailable'
};

/**
 * Central access check enforcing all security policies before a file download is permitted.
 * 
 * @param {Object} record - File metadata record from metadataService
 * @param {string|null} providedPassword - Plaintext password attempt (if any)
 * @returns {Promise<{ allowed: boolean, reason?: string, status?: number, filePath?: string }>}
 */
export async function canDownload(record, providedPassword = null) {
  if (!record) {
    return {
      allowed: false,
      reason: 'File not found or link is invalid.',
      status: 404
    };
  }

  // 1. File lifecycle status check
  if (record.status !== FILE_STATUS.ACTIVE) {
    const isDeleting = record.status === FILE_STATUS.DELETING || record.status === FILE_STATUS.DELETED;
    return {
      allowed: false,
      reason: isDeleting ? 'This file is no longer available.' : 'This file is currently unavailable.',
      status: isDeleting ? 410 : 403
    };
  }

  // 2. Link expiration check
  const now = Date.now();
  const expiryTime = new Date(record.expiresAt).getTime();
  if (isNaN(expiryTime) || now > expiryTime) {
    return {
      allowed: false,
      reason: 'This sharing link has expired.',
      status: 410 // 410 Gone indicates expired resource
    };
  }

  // 3. Download allowance check (Feature A: Download limits & one-time links)
  if (record.downloadLimit !== null && record.downloadLimit !== undefined) {
    const currentCount = typeof record.downloadCount === 'number' ? record.downloadCount : 0;
    if (currentCount >= record.downloadLimit) {
      return {
        allowed: false,
        reason: 'This download link has reached its maximum download limit.',
        status: 410
      };
    }
  }

  // 3. Scan status check (Centralized hook for future ClamAV integration)
  // If infected or blocked by scanner in future phase, deny access immediately.
  if (record.scanStatus === SCAN_STATUS.INFECTED) {
    return {
      allowed: false,
      reason: 'Access denied: File was flagged as potentially malicious.',
      status: 403
    };
  }
  // In future ClamAV phase: uncomment strict clean check:
  // if (record.scanStatus !== SCAN_STATUS.CLEAN) {
  //   return { allowed: false, reason: 'File scan pending or unverified.', status: 403 };
  // }

  // 4. Physical file existence on server disk
  const existsOnDisk = await fileExists(record.storedName);
  if (!existsOnDisk) {
    return {
      allowed: false,
      reason: 'The requested file could not be found in storage.',
      status: 404
    };
  }

  // 5. Password protection verification
  if (record.passwordHash && record.passwordSalt) {
    if (!providedPassword) {
      return {
        allowed: false,
        reason: 'Password required to download this file.',
        status: 401
      };
    }

    const isMatch = await verifyPassword(
      providedPassword,
      record.passwordHash,
      record.passwordSalt
    );

    if (!isMatch) {
      return {
        allowed: false,
        reason: 'Incorrect password.',
        status: 401
      };
    }
  }

  // All security checks passed
  const filePath = getSafeFilePath(record.storedName);
  return {
    allowed: true,
    filePath
  };
}
