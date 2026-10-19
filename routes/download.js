import express from 'express';
import { getFileByToken } from '../services/metadataService.js';
import { canDownload } from '../services/accessService.js';
import { passwordRateLimiter } from '../middleware/rateLimiter.js';

const router = express.Router();

/**
 * GET /api/files/:token
 * Returns public metadata for a shared file (used by the download page).
 * Never exposes storage paths, internal IDs, or password hashes.
 */
router.get('/:token', async (req, res, next) => {
  try {
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

    if (record.status !== 'active') {
      return res.status(403).json({
        error: 'This file is currently unavailable.'
      });
    }

    return res.json({
      token: record.shareToken,
      originalName: record.originalName,
      size: record.size,
      hasPassword: !!record.passwordHash,
      expiresAt: record.expiresAt,
      scanStatus: record.scanStatus
    });
  } catch (err) {
    next(err);
  }
});

/**
 * Common handler for streaming the file download.
 */
async function processDownload(req, res, password = null) {
  const { token } = req.params;
  const record = await getFileByToken(token);

  if (!record) {
    return res.status(404).json({ error: 'File not found or link is invalid.' });
  }

  const access = await canDownload(record, password);

  if (!access.allowed) {
    if (access.status === 401 && req.recordPasswordFailure) {
      req.recordPasswordFailure();
    }
    return res.status(access.status || 403).json({ error: access.reason });
  }

  // Clear any failed password attempts on successful access
  if (req.clearPasswordFailures) {
    req.clearPasswordFailures();
  }

  // Safe file delivery via Express res.download
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.download(access.filePath, record.originalName, (err) => {
    if (err && !res.headersSent) {
      res.status(500).json({ error: 'Failed to deliver the requested file.' });
    }
  });
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
