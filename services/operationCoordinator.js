/**
 * Operation Coordinator Service
 *
 * Tracks active file streams and operations within the single-process Node.js runtime.
 * Prevents race conditions such as the background cleanup worker deleting a file
 * while a client download is in progress.
 */

const activeDownloads = new Map(); // fileId -> count of active streams
const activeTempFiles = new Set(); // absolute paths of temp files currently in use

/**
 * Acquires a read lease for an active download operation.
 * 
 * @param {string} fileId
 * @returns {Function} release callback to invoke on finish/close/error
 */
export function acquireDownloadLease(fileId) {
  const current = activeDownloads.get(fileId) || 0;
  activeDownloads.set(fileId, current + 1);

  let released = false;
  return () => {
    if (released) return;
    released = true;
    const remaining = (activeDownloads.get(fileId) || 1) - 1;
    if (remaining <= 0) {
      activeDownloads.delete(fileId);
    } else {
      activeDownloads.set(fileId, remaining);
    }
  };
}

/**
 * Checks if a file currently has active downloads in progress.
 * 
 * @param {string} fileId
 * @returns {boolean}
 */
export function hasActiveDownloads(fileId) {
  return (activeDownloads.get(fileId) || 0) > 0;
}

/**
 * Returns current count of active download streams for a file.
 *
 * @param {string} fileId
 * @returns {number}
 */
export function getActiveDownloadCount(fileId) {
  return activeDownloads.get(fileId) || 0;
}

/**
 * Marks a temporary file as in use so that the background temp sweeper will not
 * unlink it. Needed because a very slow download (or a very large file) can keep
 * a decrypted staging file open for longer than the sweeper's age threshold.
 *
 * @param {string} tempFilePath - Absolute path of the temporary file
 */
export function registerActiveTempFile(tempFilePath) {
  if (typeof tempFilePath === 'string' && tempFilePath) {
    activeTempFiles.add(tempFilePath);
  }
}

/**
 * Releases a previously registered temporary file.
 *
 * @param {string} tempFilePath
 */
export function releaseActiveTempFile(tempFilePath) {
  if (typeof tempFilePath === 'string' && tempFilePath) {
    activeTempFiles.delete(tempFilePath);
  }
}

/**
 * Checks whether a temporary file is currently registered as in use.
 *
 * @param {string} tempFilePath
 * @returns {boolean}
 */
export function isTempFileInUse(tempFilePath) {
  return activeTempFiles.has(tempFilePath);
}

/**
 * Returns the number of temporary files currently in use. Diagnostics only.
 *
 * @returns {number}
 */
export function getActiveTempFileCount() {
  return activeTempFiles.size;
}
