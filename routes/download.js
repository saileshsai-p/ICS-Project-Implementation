import express from 'express';
import { getFileByToken, consumeDownloadAllowance } from '../services/metadataService.js';
import { canDownload } from '../services/accessService.js';
import { passwordRateLimiter } from '../middleware/rateLimiter.js';
import { decryptStorageToTemp, cleanupTempDecryptedFile } from '../services/encryptionService.js';
import { calculateFileSha256, verifySha256Digest } from '../services/fileIntegrityService.js';
import {
  acquireDownloadLease,
  registerActiveTempFile,
  releaseActiveTempFile
} from '../services/operationCoordinator.js';
import { normalizeEmail } from '../services/userService.js';

const router = express.Router();

/**
 * GET /api/files/:token
 * Returns public metadata for a shared file (used by the download page).
 * Enforces recipient-based authorization if the file is restricted.
 * Never exposes storage paths, internal IDs, encryption keys, password hashes, or authorized recipient lists.
 */
router.get('/:token', async (req, res, next) => {
  try {
    // Prevent browser from caching metadata with stale remaining allowance counts
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const { token } = req.params;
    const record = await getFileByToken(token);

    if (!record) {
      return res.status(404).json({
        error: 'File not found. The sharing link may be invalid.'
      });
    }

    // Check expiration
    const isExpired = Date.now() > new Date(record.expiresAt).getTime();
    if (isExpired) {
      return res.status(410).json({
        error: 'This sharing link has expired.',
        expired: true,
        originalName: record.originalName
      });
    }

    // Check lifecycle status
    if (record.status !== 'active') {
      const isDeleting = record.status === 'deleting' || record.status === 'deleted';
      return res.status(isDeleting ? 410 : 403).json({
        error: isDeleting ? 'This file is no longer available.' : 'This file is currently unavailable.',
        unavailable: true,
        originalName: record.originalName
      });
    }

    // Check download limit
    const currentCount = typeof record.downloadCount === 'number' ? record.downloadCount : 0;
    const isExhausted = record.downloadLimit !== null && record.downloadLimit !== undefined && currentCount >= record.downloadLimit;
    if (isExhausted) {
      return res.status(410).json({
        error: 'This download link has reached its maximum download limit.',
        limitExhausted: true,
        originalName: record.originalName
      });
    }

    // Check recipient restrictions (Feature G)
    const isRestricted = Array.isArray(record.authorizedRecipients) && record.authorizedRecipients.length > 0;
    if (isRestricted) {
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required. Please log in to access this restricted file.',
          authRequired: true,
          isRestricted: true,
          redirectUrl: `/login?redirect=${encodeURIComponent(`/share/${record.shareToken}`)}`
        });
      }

      const userEmail = normalizeEmail(req.user.email);
      const isAuthorized = record.authorizedRecipients.some(
        (recipient) => normalizeEmail(recipient) === userEmail
      );

      if (!isAuthorized) {
        return res.status(403).json({
          error: 'Access denied: Your account is not authorized to access this file.',
          accessDenied: true,
          isRestricted: true
        });
      }
    }

    const remainingDownloads = record.downloadLimit !== null && record.downloadLimit !== undefined
      ? Math.max(0, record.downloadLimit - currentCount)
      : null;

    return res.json({
      token: record.shareToken,
      originalName: record.originalName,
      size: record.size,
      hasPassword: !!record.passwordHash,
      expiresAt: record.expiresAt,
      scanStatus: record.scanStatus,
      downloadPolicy: record.downloadPolicy || 'unlimited',
      downloadLimit: record.downloadLimit,
      downloadCount: currentCount,
      remainingDownloads,
      isRestricted
    });
  } catch (err) {
    next(err);
  }
});

/**
 * Common handler for authorized file delivery.
 * Enforces access control, recipient authorization, GCM decryption, SHA-256 verification, and atomic allowance consumption.
 */
async function processDownload(req, res, password = null) {
  const { token } = req.params;
  const record = await getFileByToken(token);

  if (!record) {
    return res.status(404).json({ error: 'File not found or link is invalid.' });
  }

  // 1. Centralized access authorization check (passes req.user for recipient validation)
  const access = await canDownload(record, password, req.user);

  if (!access.allowed) {
    if (access.status === 401 && !access.authRequired && req.recordPasswordFailure) {
      req.recordPasswordFailure();
    }
    return res.status(access.status || 403).json({
      error: access.reason,
      authRequired: !!access.authRequired,
      accessDenied: !!access.accessDenied
    });
  }

  // Clear any failed password attempts on successful access
  if (req.clearPasswordFailures) {
    req.clearPasswordFailures();
  }

  let tempDecryptedPath = null;
  let fileDeliveryPath = access.filePath;
  let releaseLease = null;

  // 2. Acquire the read lease BEFORE touching storage. The lease must cover the
  //    whole operation - decryption reads the ciphertext, so a cleanup cycle
  //    running between authorization and decryption would otherwise be able to
  //    unlink the file mid-read.
  releaseLease = acquireDownloadLease(record.id);

  /**
   * Releases the lease and discards any decrypted temporary file, then sends a
   * failure response. Every failure path must go through this so that a refused
   * download can never leak a lease (which would block cleanup forever) or
   * leave plaintext staged on disk.
   */
  const failClosed = async (status, errorMessage) => {
    if (tempDecryptedPath) {
      releaseActiveTempFile(tempDecryptedPath);
      await cleanupTempDecryptedFile(tempDecryptedPath);
      tempDecryptedPath = null;
    }
    if (releaseLease) {
      releaseLease();
      releaseLease = null;
    }
    return res.status(status).json({ error: errorMessage });
  };

  try {
    // 3. Cryptographic decryption and integrity verification
    if (record.encryption && record.encryption.enabled) {
      // Decrypt ciphertext from storage into a private temporary file.
      // Any GCM authentication or key-unwrap failure throws here and is handled
      // by the catch block below; no bytes reach the client.
      try {
        tempDecryptedPath = await decryptStorageToTemp(record.storedName, record.encryption);
        registerActiveTempFile(tempDecryptedPath);
      } catch (cryptoErr) {
        // Log internally for diagnostics. Never log key material, plaintext or
        // the decrypted path contents - only the record identity and reason.
        console.error(
          `[Download] Decryption/authentication failure for record ${record.id} ` +
          `(storedName=${record.storedName}): ${cryptoErr.message}`
        );
        return failClosed(500, 'The requested file could not be verified and was not delivered.');
      }

      // Verify SHA-256 integrity of the recovered plaintext against the upload-time digest
      const actualDigest = await calculateFileSha256(tempDecryptedPath);

      if (!record.integrity || !verifySha256Digest(actualDigest, record.integrity.expectedDigest)) {
        console.error(
          `[Download] SHA-256 integrity mismatch for record ${record.id} ` +
          `(storedName=${record.storedName}): decrypted content does not match the stored digest. ` +
          'File was NOT delivered.'
        );
        return failClosed(
          500,
          'File integrity verification failed. The decrypted content does not match the expected cryptographic digest.'
        );
      }

      fileDeliveryPath = tempDecryptedPath;
    } else if (record.integrity && record.integrity.expectedDigest) {
      // Unencrypted legacy file with integrity record
      const actualDigest = await calculateFileSha256(access.filePath);
      if (!verifySha256Digest(actualDigest, record.integrity.expectedDigest)) {
        console.error(
          `[Download] SHA-256 integrity mismatch for unencrypted legacy record ${record.id}. ` +
          'File was NOT delivered.'
        );
        return failClosed(500, 'File integrity verification failed.');
      }
    }

    // 4. Atomically consume download allowance immediately before streaming begins
    const consumption = await consumeDownloadAllowance(record.id);
    if (!consumption.success) {
      return failClosed(consumption.status || 410, consumption.reason);
    }

    // 5. Setup cleanup for response completion or premature client disconnection
    let cleanedUp = false;
    const cleanupResources = async () => {
      if (cleanedUp) return;
      cleanedUp = true;
      if (tempDecryptedPath) {
        releaseActiveTempFile(tempDecryptedPath);
        await cleanupTempDecryptedFile(tempDecryptedPath);
        tempDecryptedPath = null;
      }
      if (releaseLease) {
        releaseLease();
        releaseLease = null;
      }
    };

    res.on('finish', cleanupResources);
    res.on('close', cleanupResources);

    // 6. Safe file delivery via Express res.download
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Expose-Headers', 'X-Download-Remaining, X-Download-Count, X-Download-Limit');

    const remainingDownloads = consumption.downloadLimit !== null && consumption.downloadLimit !== undefined
      ? Math.max(0, consumption.downloadLimit - consumption.downloadCount)
      : null;

    if (remainingDownloads !== null) {
      res.setHeader('X-Download-Remaining', String(remainingDownloads));
      res.setHeader('X-Download-Count', String(consumption.downloadCount));
      res.setHeader('X-Download-Limit', String(consumption.downloadLimit));
    }

    res.download(fileDeliveryPath, record.originalName, async (err) => {
      await cleanupResources();
      if (err && !res.headersSent) {
        res.status(500).json({ error: 'Failed to deliver the requested file.' });
      }
    });

  } catch (err) {
    // Log internally for diagnostics; the client sees a generic message only.
    console.error(
      `[Download] Failed to prepare record ${record?.id ?? 'unknown'} for delivery: ${err.message}`
    );

    if (tempDecryptedPath) {
      releaseActiveTempFile(tempDecryptedPath);
      await cleanupTempDecryptedFile(tempDecryptedPath);
    }
    if (releaseLease) {
      releaseLease();
    }
    // Fail closed: never expose internal stack traces or paths
    return res.status(500).json({
      error: 'An error occurred while verifying and preparing the file for download.'
    });
  }
}

/**
 * GET /api/files/:token/download
 * Used for direct downloads (when no password is required).
 */
router.get('/:token/download', async (req, res, next) => {
  try {
    await processDownload(req, res, null);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/files/:token/download
 * Used for password-protected downloads (passwords are passed in request body, NEVER in URLs).
 */
router.post('/:token/download', passwordRateLimiter, async (req, res, next) => {
  try {
    const password = req.body?.password || null;
    await processDownload(req, res, password);
  } catch (err) {
    next(err);
  }
});

export default router;
