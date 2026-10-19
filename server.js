import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { initStorage } from './services/fileService.js';
import { initMetadataStore } from './services/metadataService.js';
import { securityHeaders } from './middleware/securityHeaders.js';
import { errorHandler } from './middleware/errorHandler.js';

import uploadRoutes from './routes/upload.js';
import downloadRoutes from './routes/download.js';
import pageRoutes from './routes/pages.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, 'public');

export const app = express();
const PORT = process.env.PORT || 3000;

// Security headers applied globally
app.use(securityHeaders);

// Body parsers for JSON and URL-encoded forms (used in password download)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets exclusively from public/
app.use(express.static(PUBLIC_DIR));

// Page routes (Homepage and Download Page)
app.use('/', pageRoutes);

// API routes
app.use('/api/files', uploadRoutes);
app.use('/api/files', downloadRoutes);

// 404 handler for unmatched routes
app.use((req, res) => {
  if (req.accepts('html')) {
    return res.status(404).send('<!DOCTYPE html><html><head><title>404 Not Found</title></head><body style="background:#0b0f19;color:#fff;font-family:sans-serif;text-align:center;padding:50px;"><h1>404 - Not Found</h1><p>The page or file you requested does not exist.</p><a href="/" style="color:#06b6d4;">Return to Homepage</a></body></html>');
  }
  res.status(404).json({ error: 'Endpoint not found' });
});

// Centralized error handler
app.use(errorHandler);

/**
 * Initializes storage directories and starts the HTTP server.
 */
export async function startServer(port = PORT) {
  await initStorage();
  await initMetadataStore();

  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      console.log(`[Secure File Sharing] Server running at http://localhost:${port}`);
      resolve(server);
    });
  });
}

// Start immediately if executed directly via Node
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer().catch((err) => {
    console.error('Fatal startup error:', err);
    process.exit(1);
  });
}
