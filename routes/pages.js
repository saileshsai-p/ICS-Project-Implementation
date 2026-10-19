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

/**
 * GET /login
 * User Login Page
 */
router.get('/login', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

/**
 * GET /register
 * User Registration Page
 */
router.get('/register', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'register.html'));
});

export default router;
