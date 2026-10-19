import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { uploadMiddleware } from '../middleware/uploadValidation.js';
import { generateStoredName, cleanupFile } from '../services/fileService.js';
import { hashPassword } from '../services/passwordService.js';
import { addFileRecord } from '../services/metadataService.js';
import { FILE_STATUS } from '../services/accessService.js';
import { SCAN_STATUS, scanFile } from '../services/malwareScanner.js';
import { calculateFileSha256 } from '../services/fileIntegrityService.js';
import { encryptFileToStorage } from '../services/encryptionService.js';

const router = express.Router();

// Flexible expiry duration bounds
const MIN_EXPIRY_MS = 1 * 60 * 1000; // 1 minute minimum
const MAX_EXPIRY_DAYS = parseInt(process.env.MAX_EXPIRY_DAYS || '365', 10);
const MAX_EXPIRY_MS = MAX_EXPIRY_DAYS * 24 * 60 * 60 * 1000; // Up to any number of days (default 365 days)

/**
 * Parses expiry input string or value/unit pair into milliseconds.
 * Supports: '1m', '5m', '1h', '24h', '7d', '30d', or value + unit.
 */
function parseExpiryToMs(expiryInput, expiryValue, expiryUnit) {
  // If explicit numeric value and unit are supplied
  if (expiryValue !== undefined && expiryValue !== null && expiryValue !== '') {
    const val = parseInt(expiryValue, 10);
    if (!isNaN(val) && val > 0) {
      const unit = String(expiryUnit || 'h').toLowerCase();
      if (unit.startsWith('m')) return val * 60 * 1000; // minutes
      if (unit.startsWith('h')) return val * 60 * 60 * 1000; // hours
      if (unit.startsWith('d')) return val * 24 * 60 * 60 * 1000; // days
    }
  }

  // If combined string is supplied (e.g., '1m', '15m', '1h', '6h', '24h', '7d', '14d')
  if (typeof expiryInput === 'string' && expiryInput.trim()) {
    const trimmed = expiryInput.trim().toLowerCase();

    // Shorthand pattern: e.g., '1m', '15m', '2h', '10d', '5 days'
    const match = trimmed.match(/^(\d+)\s*([a-z]+)?$/);
    if (match) {
      const val = parseInt(match[1], 10);
      const unit = (match[2] || 'h').toLowerCase();
      if (val > 0) {
        if (unit.startsWith('m')) return val * 60 * 1000;
        if (unit.startsWith('h')) return val * 60 * 60 * 1000;
        if (unit.startsWith('d')) return val * 24 * 60 * 60 * 1000;
      }
    }
  }

  // Default fallback: 24 hours
  return 24 * 60 * 60 * 1000;
}

/**
 * Calculates a valid expiration ISO timestamp.
 * Enforces backend bounds: minimum 1 minute, maximum permitted days.
 * @param {string} expiryInput - e.g. '1m', '1h', '24h', '7d'
 * @param {number|string} [expiryValue] - Numeric amount
 * @param {string} [expiryUnit] - 'minutes', 'hours', 'days'
 * @returns {string} ISO 8601 string
 */
function calculateExpiry(expiryInput, expiryValue, expiryUnit) {
  let durationMs = parseExpiryToMs(expiryInput, expiryValue, expiryUnit);

  if (durationMs < MIN_EXPIRY_MS) {
    durationMs = MIN_EXPIRY_MS;
  }
  if (durationMs > MAX_EXPIRY_MS) {
    durationMs = MAX_EXPIRY_MS;
  }

  return new Date(Date.now() + durationMs).toISOString();
}

/**
 * Validates and parses user-supplied download policy.
 * @param {string} policyInput - 'unlimited' | 'one_time' | 'limited'
 * @param {string|number} limitInput - Numeric limit for 'limited' policy
 * @returns {{ downloadPolicy: string, downloadLimit: number|null }}
 */
function parseDownloadPolicy(policyInput, limitInput) {
  const policy = String(policyInput || 'unlimited').toLowerCase().trim();

  if (policy === 'one_time') {
    return { downloadPolicy: 'one_time', downloadLimit: 1 };
  }

  if (policy === 'limited') {
    const parsed = parseInt(limitInput, 10);
    if (isNaN(parsed) || parsed < 1) {
      throw { status: 400, message: 'Configurable download limit must be a positive integer (at least 1).' };
    }
    return { downloadPolicy: 'limited', downloadLimit: parsed };
  }

  // Default: unlimited
  return { downloadPolicy: 'unlimited', downloadLimit: null };
}

/**
 * POST /api/files
 * Handles secure file uploads with AES-256-GCM encryption at rest,
 * SHA-256 integrity digest, download limits, optional password protection and link expiry.
 */
router.post('/', (req, res, next) => {
  uploadMiddleware(req, res, async (err) => {
    if (err) {
      return next(err);
    }

    // 1. Validate file presence
    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded. Please select a file to share.'
      });
    }

    const tempFilePath = req.file.path;
    let storedName = null;

    try {
      const { password, expiry, expiryValue, expiryUnit, downloadPolicy: rawPolicy, downloadLimit: rawLimit } = req.body;

      // 2. Validate and parse download policy
      const { downloadPolicy, downloadLimit } = parseDownloadPolicy(rawPolicy, rawLimit);

      // 3. Expiry calculation (flexible from 1 minute to any number of days)
      const expiresAt = calculateExpiry(expiry, expiryValue, expiryUnit);

      // 4. Optional password hashing using scrypt with unique salt
      let passwordData = null;
      if (password && typeof password === 'string' && password.trim().length > 0) {
        if (password.length > 128) {
          throw { status: 400, message: 'Password exceeds maximum length of 128 characters.' };
        }
        passwordData = await hashPassword(password);
      }

      // 5. Generate internal file ID, safe storage name, and share token
      const fileId = crypto.randomUUID();
      storedName = generateStoredName(req.file.originalname);
      // Generate unguessable 256-bit URL-safe share token
      const shareToken = crypto.randomBytes(32).toString('base64url');

      /* =========================================================================
       * [FUTURE CLAMAV INTEGRATION HOOK]
       * Step 1: Scan the original temporary file BEFORE encryption and permanent storage:
       * const scanResult = await scanFile(tempFilePath);
       * if (scanResult.status === SCAN_STATUS.INFECTED) {
       *   await cleanupFile(tempFilePath);
       *   return res.status(400).json({ error: 'File rejected: Potential malware detected.' });
       * }
       * ========================================================================= */

      // 6. Calculate SHA-256 integrity digest of original uploaded plaintext
      const originalPlaintextSha256 = await calculateFileSha256(tempFilePath);

      // 7. Encrypt file using AES-256-GCM into permanent private storage
      const { encryptionMeta } = await encryptFileToStorage(tempFilePath, storedName);

      // 8. Immediately remove plaintext temporary upload
      await cleanupFile(tempFilePath);

      // 9. Record metadata with versioned encryption and integrity structures
      const fileRecord = {
        id: fileId,
        shareToken,
        originalName: path.basename(req.file.originalname),
        storedName,
        mimeType: req.file.mimetype || 'application/octet-stream',
        size: req.file.size,
        passwordHash: passwordData ? passwordData.hash : null,
        passwordSalt: passwordData ? passwordData.salt : null,
        expiresAt,
        createdAt: new Date().toISOString(),
        status: FILE_STATUS.ACTIVE,
        scanStatus: SCAN_STATUS.NOT_SCANNED,
        downloadPolicy,
        downloadLimit,
        downloadCount: 0,
        storageFormat: 'encrypted-v2',
        encryption: encryptionMeta,
        integrity: {
          algorithm: 'sha256',
          expectedDigest: originalPlaintextSha256,
          version: 1
        }
      };

      await addFileRecord(fileRecord);

      // 10. Return share URL and public metadata (NEVER expose master key, wrapped keys, hashes, salts, or paths)
      return res.status(201).json({
        success: true,
        file: {
          id: fileId,
          shareToken,
          originalName: fileRecord.originalName,
          size: fileRecord.size,
          hasPassword: !!passwordData,
          expiresAt: fileRecord.expiresAt,
          scanStatus: fileRecord.scanStatus,
          downloadPolicy: fileRecord.downloadPolicy,
          downloadLimit: fileRecord.downloadLimit,
          downloadCount: fileRecord.downloadCount,
          shareUrl: `/share/${shareToken}`
        }
      });
    } catch (uploadErr) {
      // Clean up orphaned temp and permanent files on any failure
      if (tempFilePath) await cleanupFile(tempFilePath);
      if (storedName) await cleanupFile(storedName);
      next(uploadErr);
    }
  });
});

export default router;
