import express from 'express';
import { getFileByToken, consumeDownloadAllowance } from '../services/metadataService.js';
import { canDownload } from '../services/accessService.js';
import { passwordRateLimiter } from '../middleware/rateLimiter.js';
import { decryptStorageToTemp, cleanupTempDecryptedFile } from '../services/encryptionService.js';
import { calculateFileSha256, verifySha256Digest } from '../services/fileIntegrityService.js';
import { acquireDownloadLease } from '../services/operationCoordinator.js';
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

  try {
    // 2. Cryptographic decryption and integrity verification
    if (record.encryption && record.encryption.enabled) {
      // Decrypt ciphertext from storage into a private temporary file
      tempDecryptedPath = await decryptStorageToTemp(record.storedName, record.encryption);

      // Verify SHA-256 integrity of the recovered plaintext against the upload-time digest
      const actualDigest = await calculateFileSha256(tempDecryptedPath);

      if (!record.integrity || !verifySha256Digest(actualDigest, record.integrity.expectedDigest)) {
        await cleanupTempDecryptedFile(tempDecryptedPath);
        tempDecryptedPath = null;
        return res.status(500).json({
          error: 'File integrity verification failed. The decrypted content does not match the expected cryptographic digest.'
        });
      }

      fileDeliveryPath = tempDecryptedPath;
    } else if (record.integrity && record.integrity.expectedDigest) {
      // Unencrypted legacy file with integrity record
      const actualDigest = await calculateFileSha256(access.filePath);
      if (!verifySha256Digest(actualDigest, record.integrity.expectedDigest)) {
        return res.status(500).json({
          error: 'File integrity verification failed.'
        });
      }
    }

    // 3. Acquire read lease to prevent cleanup worker from deleting file during streaming
    releaseLease = acquireDownloadLease(record.id);

    // 4. Atomically consume download allowance immediately before streaming begins
    const consumption = await consumeDownloadAllowance(record.id);
    if (!consumption.success) {
      if (tempDecryptedPath) {
        await cleanupTempDecryptedFile(tempDecryptedPath);
        tempDecryptedPath = null;
      }
      if (releaseLease) {
        releaseLease();
        releaseLease = null;
      }
      return res.status(consumption.status || 410).json({ error: consumption.reason });
    }

    // 5. Setup cleanup for response completion or premature client disconnection
    let cleanedUp = false;
    const cleanupResources = async () => {
      if (cleanedUp) return;
      cleanedUp = true;
      if (tempDecryptedPath) {
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
    if (tempDecryptedPath) {
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
