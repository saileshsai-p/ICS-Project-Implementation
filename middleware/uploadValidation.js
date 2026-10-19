import multer from 'multer';
import path from 'node:path';
import crypto from 'node:crypto';
import { TEMP_DIR } from '../services/fileService.js';

export const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE_BYTES || '', 10) || 50 * 1024 * 1024; // 50MB default

// Configure Multer storage to stream into safe private temporary directory
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, TEMP_DIR);
  },
  filename: (req, file, cb) => {
    // Generate temporary unguessable name
    const tempName = `temp_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    cb(null, tempName);
  }
});

export const uploadMiddleware = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1
  }
}).single('file');
