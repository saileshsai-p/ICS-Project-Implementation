import multer from 'multer';
import { cleanupFile } from '../services/fileService.js';

export function errorHandler(err, req, res, next) {
  // Always clean up uploaded temporary file on error if one exists
  if (req.file && req.file.path) {
    cleanupFile(req.file.path).catch(() => {});
  }

  // Multer-specific error handling
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'File size exceeds the maximum permitted limit (50 MB).'
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        error: 'Only one file can be uploaded at a time.'
      });
    }
    return res.status(400).json({
      error: `Upload validation failed: ${err.message}`
    });
  }

  // Application-level errors
  const statusCode = err.status || err.statusCode || 500;
  const userMessage = statusCode < 500 ? err.message : 'An internal server error occurred. Please try again.';

  if (statusCode >= 500) {
    // Log internally without exposing to client
    console.error(`[Server Error] ${req.method} ${req.url}:`, err.message);
  }

  res.status(statusCode).json({
    error: userMessage
  });
}
