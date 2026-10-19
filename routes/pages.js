import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '../public');

const router = express.Router();

/**
 * GET /
 * File Upload Homepage
 */
router.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

/**
 * GET /share/:token
 * File Download Page for recipient
 */
router.get('/share/:token', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'download.html'));
});

export default router;
